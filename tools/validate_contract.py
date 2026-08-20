#!/usr/bin/env python3
"""Validate control-plane configuration, queue, release and doc contracts."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import sys
from pathlib import Path


# This repository is the control plane; its root and CONTROL are the same
# directory. Both names are kept so the contract paths below read unchanged.
ROOT = Path(__file__).resolve().parents[1]
CONTROL = ROOT
DEPLOY = CONTROL / "deploy"


def rust_module_files(root: Path) -> list[Path]:
    """Return a Rust module root and every filesystem-backed child module."""
    module_directory = root.with_suffix("")
    children = sorted(module_directory.rglob("*.rs")) if module_directory.is_dir() else []
    return [root, *children]


def rust_production_module_source(root: Path) -> str:
    """Read a complete Rust module tree while excluding unit-test modules."""
    return "\n".join(
        path.read_text().split("#[cfg(test)]", 1)[0]
        for path in rust_module_files(root)
    )


def load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"{path.relative_to(ROOT)}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{path.relative_to(ROOT)}: root must be an object")
    return value


def environment_example() -> set[str]:
    text = (DEPLOY / ".env.example").read_text()
    return set(re.findall(r"^([A-Z][A-Z0-9_]*)=", text, re.MULTILINE))


def compose_references() -> set[str]:
    text = "\n".join(path.read_text() for path in DEPLOY.glob("compose*.yml"))
    return set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)(?::-[^}]*)?\}", text))


def worker_queues() -> set[str]:
    text = (CONTROL / "src/worker.rs").read_text()
    match = re.search(r"const QUEUES:.*?= \[(.*?)\];", text, re.DOTALL)
    if match is None:
        raise ValueError("control-plane/src/worker.rs: QUEUES constant not found")
    return set(re.findall(r'"([a-z][a-z-]+)"', match.group(1)))


def compose_worker_queues() -> set[str]:
    text = (DEPLOY / "compose.yml").read_text()
    return set(re.findall(r'"/usr/local/bin/control-worker", "([a-z-]+)"', text))


def compose_service_block(name: str) -> str:
    text = (DEPLOY / "compose.yml").read_text()
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [a-z0-9-]+:\n|^networks:|^secrets:|\Z)", text
    )
    if match is None:
        raise ValueError(f"Compose service {name} is missing")
    return match.group(1)


def compose_anchor_environment(text: str, name: str) -> set[str]:
    match = re.search(
        rf"(?ms)^x-{re.escape(name)}:\s*&[a-z0-9-]+\n(.*?)(?=^\S|\Z)", text
    )
    if match is None:
        raise ValueError(f"Compose environment anchor {name} is missing")
    return set(re.findall(r"(?m)^  ([A-Z][A-Z0-9_]*):", match.group(1)))


def compose_service_environment(text: str, name: str) -> set[str]:
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [a-z0-9-]+:\n|^networks:)", text
    )
    if match is None:
        raise ValueError(f"Compose service {name} is missing")
    lines = match.group(1).splitlines()
    try:
        start = lines.index("    environment:") + 1
    except ValueError as error:
        raise ValueError(f"Compose service {name} has no environment block") from error
    environment: set[str] = set()
    for line in lines[start:]:
        if line and not line.startswith("      "):
            break
        key = re.match(r"      ([A-Z][A-Z0-9_]*):", line)
        if key:
            environment.add(key.group(1))
            continue
        anchor = re.match(r"      <<: \*([a-z0-9-]+)$", line)
        if anchor:
            environment.update(compose_anchor_environment(text, anchor.group(1)))
    return environment


def compose_secret_mounts(text: str) -> dict[str, set[str]]:
    section = re.search(r"(?ms)^services:\n(.*?)(?=^\S|\Z)", text)
    if section is None:
        return {}
    service_text = section.group(1)
    starts = list(re.finditer(r"(?m)^  ([a-z0-9-]+):\n", service_text))
    mounts: dict[str, set[str]] = {}
    for index, start in enumerate(starts):
        service = start.group(1)
        end = starts[index + 1].start() if index + 1 < len(starts) else len(service_text)
        block = service_text[start.end():end]
        names: set[str] = set()
        inline = re.search(r"(?m)^    secrets:\s*\[([^]]*)\]", block)
        if inline:
            names.update(
                value.strip()
                for value in inline.group(1).split(",")
                if value.strip()
            )
        multiline = re.search(r"(?ms)^    secrets:\s*\n((?:      - [^\n]+\n?)*)", block)
        if multiline:
            names.update(re.findall(r"(?m)^      - ([a-z0-9_]+)$", multiline.group(1)))
            names.update(
                re.findall(
                    r"(?m)^      - source: ([a-z0-9_]+)$", multiline.group(1)
                )
            )
        if names:
            mounts[service] = names
    return mounts


def validate_secret_mounts(
    specification: dict[str, object], compose_texts: list[str]
) -> list[str]:
    declared = specification.get("runtime_secret_mounts")
    if not isinstance(declared, dict):
        return ["configuration specification lacks runtime secret mount ownership"]
    actual: dict[str, set[str]] = {}
    for compose_text in compose_texts:
        for service, mounts in compose_secret_mounts(compose_text).items():
            actual.setdefault(service, set()).update(mounts)
    errors: list[str] = []
    for service, raw_expected in declared.items():
        if not isinstance(service, str) or not isinstance(raw_expected, list) or not all(
            isinstance(name, str) for name in raw_expected
        ):
            errors.append(f"secret mount contract for {service} is invalid")
            continue
        expected = set(raw_expected)
        if len(expected) != len(raw_expected):
            errors.append(f"secret mount contract for {service} has duplicates")
        missing = expected - actual.get(service, set())
        extra = actual.get(service, set()) - expected
        if missing or extra:
            errors.append(
                f"{service} secret mount drift: missing={sorted(missing)} "
                f"extra={sorted(extra)}"
            )
    undeclared_services = set(actual) - set(declared)
    if undeclared_services:
        errors.append(
            "Compose services have undeclared secret mounts: "
            f"{sorted(undeclared_services)}"
        )
    return errors


def validate_runtime_environment(
    specification: dict[str, object], compose_text: str
) -> list[str]:
    errors: list[str] = []
    contracts = specification.get("runtime_environment")
    required = specification.get("required_environment")
    if not isinstance(contracts, dict) or not isinstance(required, dict):
        return ["configuration specification lacks runtime environment ownership"]
    process_owners: set[str] = set()
    for service, raw_contract in contracts.items():
        if not isinstance(service, str) or not isinstance(raw_contract, dict):
            errors.append("runtime environment entries must be service objects")
            continue
        process = raw_contract.get("process")
        variables = raw_contract.get("variables")
        if not isinstance(process, str) or not isinstance(variables, list) or not all(
            isinstance(name, str) for name in variables
        ):
            errors.append(f"runtime environment contract for {service} is invalid")
            continue
        process_owners.add(process)
        expected = set(variables)
        if len(expected) != len(variables):
            errors.append(f"runtime environment contract for {service} has duplicates")
        try:
            actual = compose_service_environment(compose_text, service)
        except ValueError as error:
            errors.append(str(error))
            continue
        missing = expected - actual
        extra = actual - expected
        if missing or extra:
            errors.append(
                f"{service} environment drift: missing={sorted(missing)} "
                f"extra={sorted(extra)}"
            )
        required_for_process = required.get(process)
        if not isinstance(required_for_process, list):
            errors.append(f"runtime process {process} has no required environment contract")
        else:
            absent_required = set(required_for_process) - actual
            if absent_required:
                errors.append(
                    f"{service} omits required {process} settings: "
                    f"{sorted(absent_required)}"
                )
    host_contracts = specification.get("host_runtime_environment", {})
    if not isinstance(host_contracts, dict):
        errors.append("host runtime environment ownership must be an object")
    else:
        for service, raw_contract in host_contracts.items():
            if not isinstance(service, str) or not isinstance(raw_contract, dict):
                errors.append("host runtime environment entries must be service objects")
                continue
            process = raw_contract.get("process")
            variables = raw_contract.get("variables")
            if not isinstance(process, str) or not isinstance(variables, list) or not all(
                isinstance(name, str) for name in variables
            ):
                errors.append(f"host runtime environment contract for {service} is invalid")
                continue
            process_owners.add(process)
            required_for_process = required.get(process)
            if not isinstance(required_for_process, list):
                errors.append(f"host runtime process {process} has no required environment contract")
            else:
                absent_required = set(required_for_process) - set(variables)
                if absent_required:
                    errors.append(
                        f"{service} omits required {process} settings: "
                        f"{sorted(absent_required)}"
                    )
    missing_processes = set(required) - process_owners
    if missing_processes:
        errors.append(
            "required processes lack a runtime environment owner: "
            f"{sorted(missing_processes)}"
        )
    return errors


def validate_secret_boundaries() -> list[str]:
    errors: list[str] = []
    forbidden = {
        "control-api": ["CONTROL_RAUTHY_ADMIN_KEY", "CONTROL_INVITATION_SIGNING_KEYS_FILE", "BACKUP_AGE_IDENTITY_FILE"],
        "worker-email": ["CONTROL_SECRET_ROOT", "CONTROL_DEPLOYMENT_DRIVER_TOKEN", "CONTROL_EXTRACTION_BROKER_TOKEN", "CONTROL_RAUTHY_ADMIN_KEY"],
        "worker-invoice": ["CONTROL_DEPLOYMENT_DRIVER_TOKEN", "CONTROL_RAUTHY_ADMIN_KEY", "MAIL_WEBHOOK_TOKEN"],
        "worker-inventory": ["CONTROL_DEPLOYMENT_DRIVER_TOKEN", "CONTROL_RAUTHY_ADMIN_KEY", "MAIL_WEBHOOK_TOKEN"],
        "worker-lifecycle": ["CONTROL_SECRET_ROOT", "CONTROL_RAUTHY_ADMIN_KEY", "CONTROL_EXTRACTION_BROKER_TOKEN", "BACKUP_AGE_IDENTITY_FILE"],
        "worker-privacy": ["CONTROL_SECRET_ROOT", "CONTROL_DEPLOYMENT_DRIVER_TOKEN", "CONTROL_RAUTHY_ADMIN_KEY", "CONTROL_EXTRACTION_BROKER_TOKEN", "MAIL_WEBHOOK_TOKEN"],
        "backup-scheduler": ["BACKUP_AGE_IDENTITY_FILE", "RESTORE_S3_SECRET_ACCESS_KEY", "CONTROL_SECRET_ROOT"],
    }
    for service, names in forbidden.items():
        try:
            block = compose_service_block(service)
        except ValueError as error:
            errors.append(str(error))
            continue
        for name in names:
            if re.search(rf"\b{re.escape(name)}\b", block):
                errors.append(f"{service} receives forbidden capability {name}")
    compose = (DEPLOY / "compose.yml").read_text()
    socket_services = re.findall(
        r"(?ms)^  ([a-z0-9-]+):\n(?:(?!^  [a-z0-9-]+:\n).)*?/var/run/docker\.sock",
        compose,
    )
    if socket_services != ["docker-driver"]:
        errors.append(f"Docker socket boundary is unsafe: {socket_services}")
    privacy_key_services = []
    for service in re.findall(r"(?m)^  ([a-z0-9-]+):\n", compose):
        try:
            block = compose_service_block(service)
        except ValueError:
            continue
        if "CONTROL_PRIVACY_LOOKUP_KEY" in block:
            privacy_key_services.append(service)
    if privacy_key_services != ["worker-lifecycle", "worker-privacy"]:
        errors.append(
            "privacy lookup key boundary is unsafe: "
            f"{privacy_key_services}"
        )
    export_key_services = []
    for service in re.findall(r"(?m)^  ([a-z0-9-]+):\n", compose):
        try:
            block = compose_service_block(service)
        except ValueError:
            continue
        if "CONTROL_PRIVACY_EXPORT_KEY" in block:
            export_key_services.append(service)
    if export_key_services != ["control-api", "worker-privacy"]:
        errors.append(
            "privacy export key boundary is unsafe: "
            f"{export_key_services}"
        )
    production_part = rust_production_module_source(CONTROL / "src/docker_driver.rs")
    if 'env!("CARGO_PKG_VERSION")' in production_part:
        errors.append("deployment driver uses the Rust package version as artifact identity")
    try:
        specification = load_json(DEPLOY / "configuration-spec.json")
    except ValueError as error:
        errors.append(str(error))
    else:
        compose_text = "\n".join(
            path.read_text() for path in sorted(DEPLOY.glob("compose*.yml"))
        )
        for name in specification.get("secrets", []):
            if re.search(rf"\$\{{{re.escape(str(name))}(?::[^}}]*)?\}}", compose_text):
                errors.append(
                    f"Compose interpolates secret {name}; use a /run/secrets reference"
                )
    return errors


def local_markdown_links(path: Path) -> list[Path]:
    targets: list[Path] = []
    for raw in re.findall(r"\[[^]]+\]\(([^)]+)\)", path.read_text()):
        target = raw.split("#", 1)[0]
        if not target or "://" in target or target.startswith("mailto:"):
            continue
        targets.append((path.parent / target).resolve())
    return targets


def validate_privacy_inventory() -> list[str]:
    path = CONTROL / "privacy/data-inventory.yaml"
    text = path.read_text()
    blocks = re.split(r"(?m)^  - id: ", text)[1:]
    errors: list[str] = []
    required = {
        "fields", "subjects", "purpose", "lawful_basis", "source", "owner",
        "locations", "authorized_roles", "recipients", "retention_policy",
        "subject_lookup", "transfer",
    }
    if not blocks:
        return ["privacy inventory has no datasets"]
    migration_sql = "\n".join(
        migration.read_text() for migration in sorted((CONTROL / "migrations").glob("*.sql"))
    ).lower()
    seen: set[str] = set()
    for block in blocks:
        dataset_id = block.splitlines()[0].strip()
        if dataset_id in seen:
            errors.append(f"privacy inventory has duplicate dataset id {dataset_id}")
        seen.add(dataset_id)
        keys = set(re.findall(r"(?m)^    ([a-z_]+):", block))
        missing = required - keys
        if missing:
            errors.append(f"privacy inventory {dataset_id} is missing {sorted(missing)}")
        fields = re.search(r"(?m)^    fields: \[(.*)\]$", block)
        if fields is None:
            continue
        for table, column in re.findall(r"control\.([a-z0-9_]+)\.([a-z0-9_]+)", fields.group(1)):
            if re.search(rf"\b(?:table|on)\s+control\.{re.escape(table)}\b", migration_sql) is None:
                errors.append(f"privacy inventory {dataset_id} references unknown table control.{table}")
            if re.search(rf"\b{re.escape(column)}\b", migration_sql) is None:
                errors.append(f"privacy inventory {dataset_id} references unknown field control.{table}.{column}")
    if "production_personal_data_allowed: false" not in text:
        errors.append("privacy inventory must keep production personal data blocked pending approval")
    return errors


def validate_privacy_governance() -> list[str]:
    errors: list[str] = []
    inventory_text = (CONTROL / "privacy/data-inventory.yaml").read_text()
    inventory_ids = set(re.findall(r"(?m)^  - id: ([a-z0-9-]+)$", inventory_text))
    retention_text = (CONTROL / "privacy/retention-policy.yaml").read_text()
    retention_ids = set(re.findall(r"(?m)^  ([a-z0-9-]+): \{trigger:", retention_text))
    inventory_retention = set(
        re.findall(r"(?m)^    retention_policy: ([a-z0-9-]+)(?:\s|$)", inventory_text)
    )
    missing_retention = inventory_retention - retention_ids
    if missing_retention:
        errors.append(
            f"privacy inventory references unknown retention policies: {sorted(missing_retention)}"
        )

    processors_text = (CONTROL / "privacy/processors.yaml").read_text()
    processor_ids = set(
        re.findall(r"(?m)^  ([a-z0-9_]+): \{provider:", processors_text)
    )
    if (
        "status: approval-required" not in processors_text
        or "controller: null" not in processors_text
        or not re.search(r"(?ms)^production_gate:\n  allowed: false$", processors_text)
    ):
        errors.append("processor register must remain fail-closed until controller approval")

    try:
        record = load_json(CONTROL / "privacy/record-of-processing.json")
    except ValueError as error:
        return [str(error), *errors]
    if (
        record.get("status") != "controller-approval-required"
        or record.get("production_personal_data_allowed") is not False
        or record.get("controller") is not None
    ):
        errors.append("processing record must remain fail-closed until controller approval")
    region = record.get("processing_region_policy")
    if not isinstance(region, dict) or region != {
        "preferred": "paris",
        "fallback": "azure-west-europe",
        "boundary": "EEA",
        "non_eea_transfer_allowed": False,
    }:
        errors.append("processing record region policy must remain Paris/West Europe and EEA-only")

    activities = record.get("activities")
    if not isinstance(activities, list) or not activities:
        return [*errors, "processing record has no activities"]
    required = {
        "id", "inventory_datasets", "purposes", "data_subject_categories",
        "personal_data_categories", "processor_register_entries",
        "recipient_categories", "transfers", "erasure_time_limits",
        "security_measures",
    }
    covered: list[str] = []
    seen_activities: set[str] = set()
    for activity in activities:
        if not isinstance(activity, dict):
            errors.append("processing record activities must be objects")
            continue
        missing = required - set(activity)
        if missing:
            errors.append(
                f"processing activity {activity.get('id')} is missing {sorted(missing)}"
            )
        activity_id = activity.get("id")
        if not isinstance(activity_id, str) or activity_id in seen_activities:
            errors.append(f"processing activity id is invalid or duplicated: {activity_id}")
        else:
            seen_activities.add(activity_id)
        datasets = activity.get("inventory_datasets")
        if isinstance(datasets, list) and all(isinstance(item, str) for item in datasets):
            covered.extend(datasets)
        else:
            errors.append(f"processing activity {activity_id} has invalid inventory coverage")
        processors = activity.get("processor_register_entries")
        if isinstance(processors, list) and all(isinstance(item, str) for item in processors):
            unknown = set(processors) - processor_ids
            if unknown:
                errors.append(
                    f"processing activity {activity_id} references unknown processors: {sorted(unknown)}"
                )
        else:
            errors.append(f"processing activity {activity_id} has invalid processor entries")
    duplicates = sorted({item for item in covered if covered.count(item) > 1})
    if duplicates:
        errors.append(f"processing record duplicates inventory datasets: {duplicates}")
    missing = inventory_ids - set(covered)
    unknown = set(covered) - inventory_ids
    if missing or unknown:
        errors.append(
            f"processing record inventory drift: missing={sorted(missing)} unknown={sorted(unknown)}"
        )
    return errors


def validate() -> list[str]:
    errors: list[str] = []
    errors.extend(validate_privacy_inventory())
    errors.extend(validate_privacy_governance())
    errors.extend(validate_secret_boundaries())
    try:
        spec = load_json(DEPLOY / "configuration-spec.json")
        contract = load_json(DEPLOY / "release-contract.json")
        schema = load_json(DEPLOY / "application-release.schema.json")
    except ValueError as error:
        return [str(error)]

    errors.extend(
        validate_runtime_environment(spec, (DEPLOY / "compose.yml").read_text())
    )
    errors.extend(
        validate_secret_mounts(
            spec,
            [path.read_text() for path in sorted(DEPLOY.glob("compose*.yml"))],
        )
    )

    if spec.get("required_environment") != contract.get("required_environment"):
        errors.append("required_environment drift between config spec and release contract")
    if spec.get("optional_environment") != contract.get("optional_environment"):
        errors.append("optional_environment drift between config spec and release contract")

    release_images = contract.get("images", {})
    third_party_path = ROOT / ".github/release-third-party-images.json"
    workflow_path = ROOT / ".github/workflows/release.yml"
    try:
        third_party = load_json(third_party_path)
    except ValueError as error:
        errors.append(str(error))
        third_party = {}
    workflow_text = workflow_path.read_text(encoding="utf-8")
    built_images = set(
        re.findall(r"(?m)^\s+build_image ([a-z0-9-]+)\s", workflow_text)
    )

    # Every image must say which repository signs it. Deployment refuses an
    # image whose provenance the composed release record does not declare, so
    # an undeclared entry here is a release that cannot be adopted.
    OWN = "MakersBrain/mb-control-plane"
    undeclared = sorted(
        name for name, image in release_images.items()
        if not isinstance(image, dict) or not image.get("source_repository")
    )
    if undeclared:
        errors.append(f"images without a source_repository: {undeclared}")

    # This repository's release workflow must build exactly the images the
    # contract assigns to it -- no more, so it cannot claim another
    # repository's provenance, and no fewer, so a release cannot quietly ship
    # less than the contract promises.
    owned = {
        name for name, image in release_images.items()
        if isinstance(image, dict) and image.get("source_repository") == OWN
    }
    if built_images != owned:
        errors.append(
            "release image delivery drift: "
            f"missing={sorted(owned - built_images)} "
            f"extra={sorted(built_images - owned)}"
        )

    # The mirrored operational-support images are still declared here as runtime
    # requirements even though mb-infra builds them, so the set must stay whole.
    if set(third_party) - set(release_images):
        errors.append(
            "third-party images not in the release contract: "
            f"{sorted(set(third_party) - set(release_images))}"
        )
    for name, source in third_party.items():
        if not isinstance(source, str) or not re.fullmatch(r"\S+@sha256:[a-f0-9]{64}", source):
            errors.append(f"third-party image {name} is not digest pinned")
            continue
        contract_source = (
            release_images.get(name, {}).get("upstream_source")
            if isinstance(release_images, dict)
            and isinstance(release_images.get(name), dict)
            else None
        )
        if contract_source != source:
            errors.append(f"third-party image {name} drifts from the release contract")

    # The qualification builder lives in mb-infra now, so this can no longer
    # read it. The direction inverts: this repository *declares* the mandatory
    # checks and infra proves its implementation matches, against the contract
    # published with the release. All that can be checked here is that the
    # declaration is well formed -- a promise nobody can act on is worse than
    # no promise.
    contracted_checks = contract.get("staging_qualification", {}).get("mandatory_checks")
    if not isinstance(contracted_checks, list) or not contracted_checks:
        errors.append("staging_qualification.mandatory_checks must be a non-empty list")
    elif not all(isinstance(check, str) and check for check in contracted_checks):
        errors.append("staging_qualification.mandatory_checks must be non-empty strings")
    elif len(set(contracted_checks)) != len(contracted_checks):
        errors.append("staging_qualification.mandatory_checks contains duplicates")

    startup_entrypoints = {
        "src/bin/control-api.rs": ["api"],
        "src/bin/control-migrate.rs": ["migration"],
        "src/bin/control-container-driver.rs": ["docker_driver"],
        "src/bin/control-backup-scheduler.rs": ["backup_scheduler"],
        "src/bin/document-extraction-broker.rs": ["document_extraction_broker"],
        "src/bin/control-mail-gateway.rs": ["mail_gateway"],
        "src/bin/control-worker.rs": [
            "membership_worker", "provisioning_worker", "invoice_worker",
            "inventory_worker", "email_worker", "reconciliation_worker",
            "lifecycle_worker", "release_worker", "privacy_worker",
        ],
    }
    for source_path, processes in startup_entrypoints.items():
        source_text = (CONTROL / source_path).read_text()
        if "startup_config::validate_process" not in source_text:
            errors.append(f"{source_path} bypasses the startup configuration gate")
        for process in processes:
            if f'"{process}"' not in source_text:
                errors.append(f"{source_path} does not bind startup process {process}")

    persistence = (CONTROL / "src/persistence.rs").read_text()
    embedded = re.search(r'EMBEDDED_SCHEMA_RELEASE:\s*&str\s*=\s*"([^"]+)"', persistence)
    if embedded is None or contract.get("schema_release") != embedded.group(1):
        errors.append("embedded schema release and release contract are inconsistent")
    elif not (CONTROL / "migrations" / f"{embedded.group(1)}.sql").is_file():
        errors.append("embedded schema release does not name a migration")
    else:
        migrations = sorted((CONTROL / "migrations").glob("[0-9][0-9][0-9][0-9]_*.sql"))
        if not migrations or migrations[-1].stem != embedded.group(1):
            errors.append("embedded schema release is not the newest forward migration")

    source = set(spec.get("source_environment", []))
    defaults = set(spec.get("implicit_development_defaults", []))
    example = environment_example()
    if source != example:
        errors.append(
            "source_environment/.env.example mismatch: "
            f"missing={sorted(source - example)} extra={sorted(example - source)}"
        )
    undocumented = compose_references() - source - defaults
    if undocumented:
        errors.append(f"Compose references undocumented settings: {sorted(undocumented)}")

    bootstrap = (DEPLOY / "bootstrap-local-env.sh").read_text()
    missing_generated = [
        name for name in spec.get("bootstrap_generated", []) if f'"{name}=' not in bootstrap
    ]
    if missing_generated:
        errors.append(f"bootstrap does not generate declared settings: {missing_generated}")

    contract_queues = set(contract["processes"]["workers"]["queues"])
    source_queues = worker_queues()
    compose_queues = compose_worker_queues()
    if not (contract_queues == source_queues == compose_queues):
        errors.append(
            "worker queue drift: "
            f"contract={sorted(contract_queues)} source={sorted(source_queues)} "
            f"compose={sorted(compose_queues)}"
        )

    schema_ref = contract.get("application_release_schema")
    if not isinstance(schema_ref, str) or not (DEPLOY / schema_ref).is_file():
        errors.append("release contract application_release_schema is missing")
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        errors.append("application release schema must use JSON Schema 2020-12")
    openapi_baseline = DEPLOY / str(contract.get("public_openapi_baseline", ""))
    if not openapi_baseline.is_file():
        errors.append("released public OpenAPI baseline is missing")

    observability = contract.get("observability", {})
    alert_path = DEPLOY / str(observability.get("prometheus_rules", ""))
    if not alert_path.is_file():
        errors.append("observability Prometheus alert rules are missing")
    else:
        alert_text = alert_path.read_text()
        for metric in (
            "makersbrain_worker_fresh",
            "makersbrain_queue_oldest_due_age_seconds",
            "makersbrain_queue_dead_letters",
            "makersbrain_backup_freshness_seconds",
            "makersbrain_restore_rehearsal_age_seconds",
            "makersbrain_release_adoptions",
            "makersbrain_provider_requests_total",
            "makersbrain_integration_instances",
        ):
            if metric not in alert_text:
                errors.append(f"Prometheus rules do not cover required metric {metric}")
    for runbook in observability.get("runbooks", []):
        if not (DEPLOY / str(runbook)).resolve().is_file():
            errors.append(f"observability runbook is missing: {runbook}")
    allowed_labels = set(observability.get("privacy_safe_labels", []))
    forbidden_labels = set(observability.get("forbidden_labels", []))
    if allowed_labels & forbidden_labels:
        errors.append("observability labels are both allowed and forbidden")

    registry_contract = contract.get("capability_registry", {})
    registry_path = DEPLOY / str(registry_contract.get("path", ""))
    try:
        registry = load_json(registry_path)
        registry_bytes = registry_path.read_bytes()
    except (ValueError, OSError) as error:
        errors.append(f"capability registry is missing or invalid: {error}")
    else:
        digest = hashlib.sha256(registry_bytes).hexdigest()
        if registry_contract.get("sha256") != digest:
            errors.append("capability registry digest does not match release contract")
        if registry_contract.get("version") != registry.get("version"):
            errors.append("capability registry version does not match release contract")
        entries = registry.get("capabilities", [])
        keys = {entry.get("key") for entry in entries if isinstance(entry, dict)}
        rust_keys = set(re.findall(r'\bkey:\s*"([a-z0-9-]+)"', (CONTROL / "src/modules.rs").read_text()))
        if keys != rust_keys:
            errors.append(
                f"capability registry/Rust key drift: registry={sorted(keys)} rust={sorted(rust_keys)}"
            )
        for entry in entries:
            if not isinstance(entry, dict):
                errors.append("capability registry entries must be objects")
                continue
            missing = set(entry.get("dependencies", [])) - keys
            if missing:
                errors.append(f"capability {entry.get('key')} has missing dependencies {sorted(missing)}")
            # The Odoo modules a capability activates live in
            # MakersBrain/mb-odoo-addons, not in this repository. Checking a
            # local addons/ directory only works in a sibling-checkout
            # development tree, so it is opportunistic here. The authoritative
            # check is the cross-repository compatibility lane, which verifies
            # these keys against the installed add-on versions published in the
            # Odoo image's release metadata.
            addons_root = ROOT / "addons"
            if addons_root.is_dir():
                for module in entry.get("odoo_modules", []):
                    if not (addons_root / module / "__manifest__.py").is_file():
                        errors.append(f"capability {entry.get('key')} references missing addon {module}")

    for document in (
        ROOT / "docs/CONTROL-PLANE-ARCHITECTURE.md",
        ROOT / "docs/CONTROL-PLANE-ROADMAP.md",
        ROOT / "docs/CONTROL-PLANE-IMPROVEMENT-PLAN.md",
        CONTROL / "README.md",
    ):
        for target in local_markdown_links(document):
            if not target.exists():
                try:
                    label = target.relative_to(ROOT)
                except ValueError:
                    label = target
                errors.append(f"{document.relative_to(ROOT)} links to missing {label}")

    return errors


def main() -> int:
    errors = validate()
    if errors:
        for error in errors:
            print(f"contract error: {error}", file=sys.stderr)
        return 1
    print("control-plane configuration and release contracts are consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
