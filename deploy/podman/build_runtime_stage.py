#!/usr/bin/env python3
"""Build scoped process environment files from a value-safe runtime input."""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

import release


KEY = re.compile(r"^[A-Z][A-Z0-9_]*$")
TARGETS = {
    "control-migrate": "control-migrate.env",
    "control-api": "control-api.env",
    "document-extraction": "document-extraction.env",
    "docker-driver": "control-container-driver.env",
    "worker-membership": "control-worker-membership-provisioning.env",
    "worker-provisioning": "control-worker-tenant-provisioning.env",
    "worker-invoice": "control-worker-invoice-capture.env",
    "worker-inventory": "control-worker-inventory-capture.env",
    "worker-email": "control-worker-email-delivery.env",
    "worker-reconciliation": "control-worker-tenant-reconciliation.env",
    "worker-lifecycle": "control-worker-tenant-lifecycle.env",
    "worker-release": "control-worker-release-adoption.env",
    "worker-privacy": "control-worker-privacy-operations.env",
    "backup-scheduler": "control-backup-scheduler.env",
    "control-mail-gateway": "control-mail-gateway.env",
    "odoo": "odoo.env",
    "rauthy": "rauthy.env",
    "control-database-identities": "control-database-identities.env",
}


def fail(message: str) -> None:
    raise ValueError(message)


def setting_map(raw: object, label: str) -> dict[str, str]:
    if not isinstance(raw, dict):
        fail(f"{label} must be an object")
    values: dict[str, str] = {}
    for name, value in raw.items():
        if not isinstance(name, str) or not KEY.fullmatch(name):
            fail(f"{label} contains an invalid setting name")
        if not isinstance(value, str) or any(
            character in value for character in "\r\n\0"
        ):
            fail(f"{label} contains an invalid value for {name}")
        values[name] = value
    return values


def parse_input(path: Path) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "shared",
        "processes",
    }:
        fail("runtime input must contain only schema_version, shared and processes")
    if document["schema_version"] != 1:
        fail("runtime input schema_version must be 1")
    shared = setting_map(document["shared"], "shared runtime input")
    raw_processes = document["processes"]
    if not isinstance(raw_processes, dict):
        fail("runtime input processes must be an object")
    unknown = set(raw_processes) - set(TARGETS)
    if unknown:
        fail(f"runtime input contains unknown processes: {sorted(unknown)}")
    processes = {
        key: setting_map(value, f"runtime input process {key}")
        for key, value in raw_processes.items()
    }
    return shared, processes


def merge_inputs(
    primary: tuple[dict[str, str], dict[str, dict[str, str]]],
    secret: tuple[dict[str, str], dict[str, dict[str, str]]] | None,
) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    shared, processes = primary
    shared = dict(shared)
    processes = {key: dict(values) for key, values in processes.items()}
    if secret is None:
        return shared, processes
    secret_shared, secret_processes = secret
    collisions = set(shared) & set(secret_shared)
    if collisions:
        fail(f"runtime and secret inputs collide in shared settings: {sorted(collisions)}")
    shared.update(secret_shared)
    for key, additions in secret_processes.items():
        target = processes.setdefault(key, {})
        collisions = set(target) & set(additions)
        if collisions:
            fail(f"runtime and secret inputs collide for {key}: {sorted(collisions)}")
        target.update(additions)
    return shared, processes


def definitions(specification: dict) -> dict[str, dict]:
    combined = dict(specification["runtime_environment"])
    combined.update(specification["host_runtime_environment"])
    if set(combined) != set(TARGETS):
        fail(
            "runtime target mapping drift: "
            f"missing={sorted(set(combined) - set(TARGETS))} "
            f"extra={sorted(set(TARGETS) - set(combined))}"
        )
    return combined


def rendered_environment_contract(rendered: Path) -> dict[str, dict[str, str]]:
    contract: dict[str, dict[str, str]] = {}
    for unit in sorted(rendered.glob("*.container")):
        instance = ""
        match = re.fullmatch(r"control-workers@([a-z-]+)\.container", unit.name)
        if match:
            instance = match.group(1)
        lines = unit.read_text(encoding="utf-8").splitlines()
        hardcoded = {}
        for line in lines:
            if line.startswith("Environment="):
                assignment = line.removeprefix("Environment=")
                name, separator, value = assignment.partition("=")
                if separator:
                    hardcoded[name] = value
            if not line.startswith("EnvironmentFile="):
                continue
            raw = line.removeprefix("EnvironmentFile=").replace("%i", instance)
            try:
                target = str(Path(raw).relative_to("/etc/makersbrain"))
            except ValueError:
                continue
            if target in contract:
                fail(f"multiple rendered units use the same environment file: {target}")
            contract[target] = hardcoded
    return contract


def required_for(definition: dict, specification: dict, key: str) -> set[str]:
    required = set(specification["required_environment"].get(definition["process"], []))
    if key == "odoo":
        required.update(release.VENDOR_REQUIRED_ENVIRONMENT["odoo.container"])
    elif key == "rauthy":
        required.update(release.VENDOR_REQUIRED_ENVIRONMENT["rauthy.container"])
    elif key == "control-database-identities":
        required.update(
            release.VENDOR_REQUIRED_ENVIRONMENT["control-database-identities.container"]
        )
    return required


def unquoted(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def validate_cross_process_contract(
    process_values: dict[str, dict[str, str]],
) -> None:
    control_api = process_values.get("control-api", {})
    issuer = unquoted(control_api.get("CONTROL_OIDC_ISSUER", ""))
    discovery_url = unquoted(control_api.get("CONTROL_OIDC_DISCOVERY_URL", ""))
    listen_scheme = unquoted(
        process_values.get("rauthy", {}).get("LISTEN_SCHEME", "")
    )
    if issuer.startswith("https://"):
        if listen_scheme != "http_https":
            fail(
                "Rauthy LISTEN_SCHEME must be http_https when the control API "
                "expects an HTTPS issuer and the internal readiness origin uses HTTP"
            )
        expected_discovery_url = (
            "http://rauthy:8092/auth/v1/.well-known/openid-configuration"
        )
        if discovery_url != expected_discovery_url:
            fail(
                "CONTROL_OIDC_DISCOVERY_URL must use the private Rauthy origin "
                f"{expected_discovery_url} when the control API expects an HTTPS issuer"
            )


def build(
    specification: dict,
    rendered: Path,
    shared: dict[str, str],
    process_values: dict[str, dict[str, str]],
) -> dict[Path, str]:
    validate_cross_process_contract(process_values)
    runtime = definitions(specification)
    rendered_contract = rendered_environment_contract(rendered)
    if set(rendered_contract) != set(TARGETS.values()):
        fail(
            "rendered environment-file drift: "
            f"missing={sorted(set(TARGETS.values()) - set(rendered_contract))} "
            f"extra={sorted(set(rendered_contract) - set(TARGETS.values()))}"
        )
    secret_names = set(specification["secrets"])
    consumed_shared: set[str] = set()
    consumed_process: dict[str, set[str]] = {
        key: set() for key in process_values
    }
    output: dict[Path, str] = {}
    for key, definition in runtime.items():
        target = TARGETS[key]
        hardcoded = rendered_contract[target]
        allowed = set(definition["variables"])
        required = required_for(definition, specification, key)
        local = process_values.get(key, {})
        values = dict(shared)
        values.update(local)
        undeclared_required = required - allowed - hardcoded.keys()
        if undeclared_required:
            fail(f"{key} required variables are absent from its ownership contract: {sorted(undeclared_required)}")
        missing = required - hardcoded.keys() - values.keys()
        if missing:
            fail(f"{target} is missing required settings: {sorted(missing)}")
        lines: list[str] = []
        for name in sorted(allowed):
            if name not in values:
                continue
            value = values[name]
            if name in local:
                consumed_process[key].add(name)
            elif name in shared:
                consumed_shared.add(name)
            if name in hardcoded:
                if unquoted(value) != unquoted(hardcoded[name]):
                    fail(
                        f"runtime input {name} conflicts with rendered value for {target}"
                    )
                continue
            reference = unquoted(value)
            if (name in secret_names or release.file_secret_value(name)) and not reference.startswith("@/run/"):
                fail(f"{name} must be a scoped @/run/ file reference")
            lines.append(f"{name}={value}")
        output[Path(target)] = "\n".join(lines) + "\n"
    unused_shared = set(shared) - consumed_shared
    unused_process = {
        key: sorted(set(values) - consumed_process.get(key, set()))
        for key, values in process_values.items()
        if set(values) - consumed_process.get(key, set())
    }
    if unused_shared or unused_process:
        fail(
            "runtime input contains unused settings: "
            f"shared={sorted(unused_shared)} processes={unused_process}"
        )
    return output


def write_stage(root: Path, files: dict[Path, str]) -> None:
    if root.is_symlink() or not root.is_dir():
        fail("staging root must be a real, existing directory")
    for relative, content in files.items():
        target = root / relative
        if target.exists() or target.is_symlink():
            fail(f"refusing to overwrite staged runtime file: {relative}")
        descriptor = os.open(
            target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400
        )
        try:
            data = content.encode("utf-8")
            written = 0
            while written < len(data):
                written += os.write(descriptor, data[written:])
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Split a value-safe runtime input into process-owned environment files"
    )
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--secret-input", type=Path)
    parser.add_argument("--rendered", required=True, type=Path)
    parser.add_argument("--staging-root", required=True, type=Path)
    parser.add_argument(
        "--specification",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "configuration-spec.json",
    )
    args = parser.parse_args()
    specification = json.loads(args.specification.read_text(encoding="utf-8"))
    shared, process_values = merge_inputs(
        parse_input(args.input),
        parse_input(args.secret_input) if args.secret_input else None,
    )
    files = build(specification, args.rendered, shared, process_values)
    write_stage(args.staging_root, files)
    print(f"staged {len(files)} process environment files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
