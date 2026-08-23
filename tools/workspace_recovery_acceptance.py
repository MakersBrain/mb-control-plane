#!/usr/bin/env python3
"""Prepare and exercise one synthetic workspace tenant for recovery tests."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"
ADDONS = ROOT.parent / "mb-odoo-addons" / "addons"
WORKSPACE_RE = re.compile(r"dev[1-4]\Z")
DIGITS = {
    name: f"sha256:{character * 64}"
    for name, character in {
        "runtime_manifest": "2",
        "runtime_config": "3",
        "extension_subject": "4",
        "extension_manifest": "5",
        "extension_config": "6",
        "payload": "7",
        "bridge": "8",
    }.items()
}


def command(arguments: list[str], *, input_text: str | None = None) -> str:
    result = subprocess.run(
        arguments,
        cwd=ROOT,
        input=input_text,
        text=True,
        check=True,
        stdout=subprocess.PIPE,
    )
    return result.stdout


def compose_arguments(workspace: str) -> list[str]:
    return [
        "docker", "compose", "--project-name", f"mb-{workspace}",
        "--env-file", str(DEPLOY / ".env"),
        "-f", str(DEPLOY / "compose.yml"),
        "-f", str(DEPLOY / "compose.cloudflare.yml"),
        "-f", str(DEPLOY / "compose.workspace.yml"),
    ]


def canonical(value: object) -> bytes:
    # The fixture contains only strings, integers, arrays and objects, for which
    # sorted compact JSON is identical to the RFC 8785 form used by serde_jcs.
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def evidence(character: str) -> dict[str, str]:
    subject = f"sha256:{character * 64}"
    return {
        "reference": f"registry.example.test/evidence@{subject}",
        "subject_digest": subject,
        "sha256_digest": f"sha256:{'f' * 64}",
    }


def fixture_manifest(workspace: str, image: str) -> tuple[dict[str, object], str]:
    runtime_subject = "sha256:" + image.rsplit("@sha256:", 1)[1]
    platform = {"os": "linux", "architecture": "amd64"}
    qualified = {
        "official_source_ref": image,
        "deployment_ref": image,
        "subject_digest": runtime_subject,
        "subject_kind": "image_index",
        "platform": platform,
        "manifest_digest": DIGITS["runtime_manifest"],
        "config_digest": DIGITS["runtime_config"],
    }
    addons = {
        "mb_brand": "19.0.1.0.0",
        "mb_control_bridge": "19.0.1.0.0",
        "mb_workshop_pos": "19.0.1.0.0",
    }
    pair_input = {
        "runtime": qualified,
        "extension": {
            "subject_digest": DIGITS["extension_subject"],
            "manifest_digest": DIGITS["extension_manifest"],
            "config_digest": DIGITS["extension_config"],
        },
        "payload_digest": DIGITS["payload"],
        "bridge_contract_digest": DIGITS["bridge"],
        "addon_versions": addons,
        "qualification_result": "passed",
    }
    qualification = "sha256:" + hashlib.sha256(canonical(pair_input)).hexdigest()
    release = f"odoo-2026.08.21-{hashlib.sha256(workspace.encode()).hexdigest()[:12]}"
    manifest: dict[str, object] = {
        "schema_version": 2,
        "release_id": release,
        "source_commit": hashlib.sha256(f"{workspace}-fixture".encode()).hexdigest(),
        "built_at": "2026-08-21T12:00:00Z",
        "odoo_runtime": {
            "official_source_ref": image,
            "deployment_ref": image,
            "subject_digest": runtime_subject,
            "subject_kind": "image_index",
            "version": "19.0",
            "platforms": [{
                "platform": platform,
                "manifest_digest": DIGITS["runtime_manifest"],
                "config_digest": DIGITS["runtime_config"],
                "evidence": {
                    "sbom": evidence("9"),
                    "vulnerability_report": evidence("a"),
                    "scanner": "workspace-fixture",
                    "advisory_snapshot_at": "2026-08-21T12:00:00Z",
                    "policy_digest": f"sha256:{'b' * 64}",
                    "sbom_kind": "observed",
                    "capability_checks_digest": f"sha256:{'c' * 64}",
                },
            }],
        },
        "extension_bundle": {
            "oci_ref": f"registry.example.test/extension@{DIGITS['extension_subject']}",
            "subject_digest": DIGITS["extension_subject"],
            "subject_kind": "image_index",
            "platforms": [{
                "platform": platform,
                "manifest_digest": DIGITS["extension_manifest"],
                "config_digest": DIGITS["extension_config"],
                "payload_digest": DIGITS["payload"],
                "python_implementation": "cpython",
                "python_abi": "cp312",
                "python_platform": "linux_x86_64",
                "dependency_inventory_digest": f"sha256:{'d' * 64}",
                "lock_file_digest": f"sha256:{'e' * 64}",
                "qualified_odoo_runtime": qualified,
                "signature": evidence("b"),
                "sbom": evidence("c"),
                "vulnerability_report": evidence("d"),
            }],
        },
        "pair_qualifications": [{
            "platform": platform,
            "odoo_manifest_digest": DIGITS["runtime_manifest"],
            "extension_manifest_digest": DIGITS["extension_manifest"],
            "payload_digest": DIGITS["payload"],
            "qualification_result": "passed",
            "qualification_digest": qualification,
        }],
        "addons": addons,
        "locked_dependencies": [],
        "upgradeable_from": [],
        "database_runtime_compatibility": {},
        "bridge_contract": "mb_control/v1",
        "bridge_contract_digest": DIGITS["bridge"],
        "schema_epoch": 1,
        "change_class": "A",
        "required_postconditions": ["registry_load", "health"],
        "capability_registry_version": 1,
        "admission_signature": evidence("e"),
    }
    return manifest, qualification


def sql_literal(value: object) -> str:
    encoded = json.dumps(value, separators=(",", ":"))
    if "$fixture$" in encoded:
        raise ValueError("unsafe fixture JSON")
    return f"$fixture${encoded}$fixture$"


def psql(workspace: str, sql: str) -> str:
    return command(
        ["docker", "exec", "-i", f"mb-{workspace}-postgres-1", "psql",
         "--set=ON_ERROR_STOP=1", "-U", "postgres", "-d", "mb_control", "-At"],
        input_text=sql,
    )


def state_path(workspace: str) -> Path:
    return DEPLOY / "workspaces" / workspace / "recovery-acceptance.json"


def load_state(workspace: str) -> dict[str, str]:
    path = state_path(workspace)
    if not path.is_file():
        raise SystemExit(f"prepare the recovery fixture first: {path}")
    state = json.loads(path.read_text(encoding="utf-8"))
    if state.get("workspace") != workspace:
        raise SystemExit("recovery fixture belongs to another workspace")
    return state


def save_state(workspace: str, state: dict[str, str]) -> None:
    path = state_path(workspace)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def psql_database(workspace: str, database: str, sql: str) -> str:
    if not re.fullmatch(r"(?:mb|pl)_[0-9a-f]{32}", database):
        raise SystemExit("fixture database reference is invalid")
    return command(
        ["docker", "exec", "-i", f"mb-{workspace}-postgres-1", "psql",
         "--set=ON_ERROR_STOP=1", "-U", "postgres", "-d", database, "-At"],
        input_text=sql,
    )


def record_recovery(workspace: str, recovery: uuid.UUID, result: dict[str, object]) -> None:
    document = sql_literal(result)
    psql(workspace, f"""
with response as (select {document}::jsonb as value)
update control.workshop_recovery_points r set
 state='ready', storage_ref=response.value->>'storage_ref',
 size_bytes=(response.value->>'size_bytes')::bigint, ready_at=now(),
 verification_state='verified', verified_at=now(),
 manifest_digest=response.value->>'manifest_digest',
 format_version=response.value->>'format_version',
 storage_location=response.value->>'storage_location',
 source_release=response.value->>'source_release',
 paperless_version=response.value->>'paperless_version',
 encryption_key_id=response.value->>'encryption_key_id',
 object_prefix=response.value->>'object_prefix',
 expires_at=now()+make_interval(days=>coalesce((response.value->>'retention_days')::integer,7)),
 archive_object_key=response.value->>'archive_object_key',
 archive_size_bytes=(response.value->>'archive_size_bytes')::bigint,
 archive_digest=response.value->>'archive_digest'
from response where r.id='{recovery}';
delete from control.workshop_recovery_components where recovery_point_id='{recovery}';
insert into control.workshop_recovery_components(
 recovery_point_id,component,object_key,size_bytes,digest,plaintext_digest,state,verified_at)
select '{recovery}',item->>'name',item->>'path',(item->>'size_bytes')::bigint,
 item->>'sha256',item->>'plaintext_sha256','verified',now()
from jsonb_array_elements(({document}::jsonb)->'components') item;
""")


def seed(workspace: str) -> None:
    state = load_state(workspace)
    compact = uuid.UUID(state["workshop_id"]).hex
    odoo = state["database_ref"]
    paperless = f"pl_{compact}"
    marker_sql = """
create table if not exists public.mb_recovery_acceptance(
 marker text primary key, value text not null
);
insert into public.mb_recovery_acceptance(marker,value) values('workspace','baseline')
on conflict(marker) do update set value=excluded.value;
"""
    psql_database(workspace, odoo, marker_sql)
    psql_database(workspace, paperless, marker_sql)
    for volume, relative in [
        (f"mb-{workspace}-odoo-data", f"filestore/{odoo}/mb-recovery-acceptance.txt"),
        (f"mb-{workspace}-paperless-{state['workshop_id']}-data", "mb-recovery-acceptance.txt"),
    ]:
        command([
            "docker", "run", "--rm", "--user", "0:0", "-v", f"{volume}:/fixture",
            "alpine:3.22", "sh", "-ec",
            f"mkdir -p /fixture/{Path(relative).parent}; printf baseline > /fixture/{relative}",
        ])
    print(f"seeded recovery markers in {workspace}")


def backup(workspace: str, force_new: bool) -> None:
    state = load_state(workspace)
    existing = state.get("recovery_point_id")
    recovery = uuid.uuid4() if force_new or not existing else uuid.UUID(existing)
    if force_new or not existing:
        psql(workspace, f"""
insert into control.workshop_recovery_points(
 id,workshop_id,database_id,kind,label,requested_by,component_scope,format_version)
values('{recovery}','{state['workshop_id']}','{state['database_id']}','backup',
 'Workspace acceptance backup','{state['owner_id']}',array['odoo','paperless'],
 'mb-workshop-recovery-v2');
""")
    response = driver(
        workspace, uuid.UUID(state["workshop_id"]), "lifecycle",
        {"action": "backup", "database_id": state["database_id"],
         "recovery_point_id": str(recovery)},
        f"workspace-acceptance-backup:{recovery}",
    )
    result = response.get("recovery_point")
    if not isinstance(result, dict):
        raise SystemExit("driver backup response has no recovery point")
    record_recovery(workspace, recovery, result)
    state["recovery_point_id"] = str(recovery)
    save_state(workspace, state)
    print(f"created and recorded recovery point {recovery}")


def rehearse(workspace: str) -> None:
    state = load_state(workspace)
    recovery = uuid.UUID(state["recovery_point_id"])
    rehearsal = uuid.uuid5(recovery, "workspace-rehearsal")
    psql(workspace, f"""
insert into control.workshop_recovery_rehearsals(
    id,recovery_point_id,workshop_id,state,attempt,lease_owner,lease_token,lease_expires_at)
values(
    '{rehearsal}','{recovery}','{state['workshop_id']}','running',1,
    gen_random_uuid(),gen_random_uuid(),now()+interval '20 minutes')
on conflict(id) do update set
    state='running',attempt=1,started_at=now(),finished_at=null,safe_error=null,
    next_attempt_at=null,lease_owner=gen_random_uuid(),lease_token=gen_random_uuid(),
    lease_expires_at=now()+interval '20 minutes';
""")
    try:
        driver(
            workspace, uuid.UUID(state["workshop_id"]), "rehearse",
            {"recovery_point_id": str(recovery)},
            f"workspace-acceptance-rehearse:{recovery}",
        )
    except Exception:
        psql(workspace, f"update control.workshop_recovery_rehearsals set state='failed',safe_error='acceptance_failed',finished_at=now(),next_attempt_at=null,lease_owner=null,lease_token=null,lease_expires_at=null where id='{rehearsal}';")
        raise
    psql(workspace, f"update control.workshop_recovery_rehearsals set state='succeeded',safe_error=null,finished_at=now(),next_attempt_at=null,lease_owner=null,lease_token=null,lease_expires_at=null where id='{rehearsal}';")
    print(f"rehearsed recovery point {recovery}")


def mutate(workspace: str) -> None:
    state = load_state(workspace)
    compact = uuid.UUID(state["workshop_id"]).hex
    for database in [state["database_ref"], f"pl_{compact}"]:
        psql_database(
            workspace, database,
            "update public.mb_recovery_acceptance set value='mutated' where marker='workspace';\n",
        )
    for volume, relative in [
        (f"mb-{workspace}-odoo-data", f"filestore/{state['database_ref']}/mb-recovery-acceptance.txt"),
        (f"mb-{workspace}-paperless-{state['workshop_id']}-data", "mb-recovery-acceptance.txt"),
    ]:
        command(["docker", "run", "--rm", "--user", "0:0", "-v", f"{volume}:/fixture",
                 "alpine:3.22", "sh", "-ec", f"printf mutated > /fixture/{relative}"])
    print(f"mutated recovery markers in {workspace}")


def restore(workspace: str) -> None:
    state = load_state(workspace)
    recovery = uuid.UUID(state["recovery_point_id"])
    pending = state.get("pending_safety_recovery_point_id")
    safety = uuid.UUID(pending) if pending else uuid.uuid4()
    if not pending:
        psql(workspace, f"""
insert into control.workshop_recovery_points(
 id,workshop_id,database_id,kind,label,requested_by,component_scope,format_version)
values('{safety}','{state['workshop_id']}','{state['database_id']}','backup',
 'Workspace acceptance pre-restore safety backup','{state['owner_id']}',
 array['odoo','paperless'],'mb-workshop-recovery-v2');
""")
        state["pending_safety_recovery_point_id"] = str(safety)
        save_state(workspace, state)
    response = driver(
        workspace, uuid.UUID(state["workshop_id"]), "lifecycle",
        {"action": "restore", "database_id": state["database_id"],
         "recovery_point_id": str(recovery), "safety_recovery_point_id": str(safety),
         "erasure_replay_required": False},
        f"workspace-acceptance-restore:{recovery}:{safety}",
    )
    if response.get("restore_status") != "restored":
        raise SystemExit(f"restore did not complete: {response.get('restore_status')}")
    psql(workspace, f"update control.odoo_databases set state='ready',last_restored_at=now() where id='{state['database_id']}';")
    paperless = f"mb-{workspace}-paperless-{uuid.UUID(state['workshop_id']).hex}"
    command(["docker", "start", paperless])
    for _ in range(60):
        health = command([
            "docker", "inspect", paperless, "--format",
            "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}",
        ]).strip()
        if health == "healthy":
            break
        if health in {"dead", "exited"}:
            raise SystemExit(f"Paperless stopped after restore ({health})")
        time.sleep(1)
    else:
        raise SystemExit("Paperless did not become healthy after restore")
    state["safety_recovery_point_id"] = str(safety)
    state.pop("pending_safety_recovery_point_id", None)
    save_state(workspace, state)
    print(f"restored recovery point {recovery}; safety point {safety}")


def verify(workspace: str) -> None:
    state = load_state(workspace)
    compact = uuid.UUID(state["workshop_id"]).hex
    for database in [state["database_ref"], f"pl_{compact}"]:
        value = psql_database(
            workspace, database,
            "select value from public.mb_recovery_acceptance where marker='workspace';\n",
        ).strip()
        if value != "baseline":
            raise SystemExit(f"database recovery marker is {value!r} in {database}")
    for volume, relative in [
        (f"mb-{workspace}-odoo-data", f"filestore/{state['database_ref']}/mb-recovery-acceptance.txt"),
        (f"mb-{workspace}-paperless-{state['workshop_id']}-data", "mb-recovery-acceptance.txt"),
    ]:
        value = command(["docker", "run", "--rm", "-v", f"{volume}:/fixture:ro",
                         "alpine:3.22", "cat", f"/fixture/{relative}"])
        if value != "baseline":
            raise SystemExit(f"file recovery marker is {value!r} in {volume}")
    print(f"verified restored database and file markers in {workspace}")


def driver(workspace: str, tenant: uuid.UUID, action: str, payload: object, key: str) -> dict[str, object]:
    script = (
        'token=$(cat /run/secrets/deployment_driver_token); '
        f'curl --fail-with-body --silent --show-error -X POST '
        f'-H "Authorization: Bearer $token" -H "Content-Type: application/json" '
        f'-H "Idempotency-Key: {key}" --data-binary @- '
        f'http://docker-driver:8080/v1/tenants/{tenant}/{action}'
    )
    output = command(
        ["docker", "exec", "-i", f"mb-{workspace}-control-api-1", "sh", "-ec", script],
        input_text=json.dumps(payload, separators=(",", ":")),
    )
    return json.loads(output)


def prepare(workspace: str) -> None:
    if state_path(workspace).exists():
        state = load_state(workspace)
        tenant = uuid.UUID(state["workshop_id"])
        module_state = psql(
            workspace,
            "select state from control.workshop_modules "
            f"where workshop_id='{tenant}' and module_key='documents';\n",
        ).strip()
        response = driver(
            workspace,
            tenant,
            "provision",
            {
                "database_ref": state["database_ref"],
                "public_hostname": state["public_hostname"],
                "paperless_enabled": True,
                "paperless_hostname": state["paperless_hostname"],
            },
            f"workspace-fixture-reconcile:{tenant}:{uuid.uuid4()}",
        )
        if not isinstance(response.get("paperless"), dict):
            raise SystemExit("driver did not reconcile the Paperless fixture")
        if module_state == "restricted":
            driver(
                workspace,
                tenant,
                "restrict",
                {
                    "capability": "documents",
                    "database_ref": state["database_ref"],
                    "public_hostname": state["public_hostname"],
                    "paperless_hostname": state["paperless_hostname"],
                },
                f"workspace-fixture-restrict:{tenant}:{uuid.uuid4()}",
            )
        print(f"reconciled synthetic recovery tenant {tenant} in {workspace}")
        return
    if not ADDONS.is_dir():
        raise SystemExit(f"local extension tree is missing: {ADDONS}")
    model = json.loads(command([*compose_arguments(workspace), "config", "--format", "json"]))
    image = model["services"]["odoo"]["image"]
    if "@sha256:" not in image:
        raise SystemExit("workspace Odoo image is not digest-pinned")
    manifest, qualification = fixture_manifest(workspace, image)
    release = str(manifest["release_id"])
    extension_volume = f"mb-{workspace}-ext-{hashlib.sha256(workspace.encode()).hexdigest()[:16]}-{'f' * 16}"
    command([
        "docker", "volume", "create", "--label", f"mb.workspace={workspace}",
        "--label", "mb.kind=extension-volume", extension_volume,
    ])
    command([
        "docker", "run", "--rm", "-v", f"{ADDONS}:/source:ro",
        "-v", f"{extension_volume}:/target", "alpine:3.22", "sh", "-ec",
        "find /target -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +; "
        "mkdir -p /target/addons /target/python; cp -a /source/. /target/addons/",
    ])
    runtime = manifest["odoo_runtime"]
    extension = manifest["extension_bundle"]
    manifest_digest = "sha256:" + hashlib.sha256(canonical(manifest)).hexdigest()
    active = psql(workspace, "select coalesce(max(id),'') from control.application_releases where status='active';\n").strip()
    if active and active != release:
        raise SystemExit(f"workspace already has a different active release: {active}")
    insert = f"""
insert into control.application_releases(
 id,source_commit,odoo_version,odoo_subject_digest,extension_subject_digest,
 odoo_runtime,extension_bundle,pair_qualifications,manifest_digest,addon_versions,
 compatibility,bridge_contract,schema_epoch,change_class,required_postconditions,
 manifest,signature_bundle_ref,extension_signature_ref,sbom_ref,published_at,status,
 publication_idempotency_key,publication_request_digest)
values(
 '{release}','{manifest['source_commit']}','19.0','{runtime['subject_digest']}','{extension['subject_digest']}',
 {sql_literal(runtime)}::jsonb,{sql_literal(extension)}::jsonb,{sql_literal(manifest['pair_qualifications'])}::jsonb,
 '{manifest_digest}',{sql_literal(manifest['addons'])}::jsonb,'{{}}'::jsonb,'mb_control/v1',1,'A',
 {sql_literal(manifest['required_postconditions'])}::jsonb,{sql_literal(manifest)}::jsonb,
 '{manifest['admission_signature']['reference']}','{extension['platforms'][0]['signature']['reference']}',
 '{runtime['platforms'][0]['evidence']['sbom']['reference']}',now(),'active',
 'workspace-fixture:{workspace}',decode('{hashlib.sha256(release.encode()).hexdigest()}','hex'))
on conflict(id) do nothing;
insert into control.runtime_release_slots(
 runtime_key,slot,release_id,state,odoo_subject_digest,odoo_manifest_digest,
 odoo_config_digest,extension_subject_digest,extension_manifest_digest,
 extension_config_digest,payload_digest,extension_volume,pair_qualification_digest,
 bridge_contract_digest,installed_addon_versions,started_at,verified_at,activated_at,evidence)
values('shared-odoo','blue','{release}','active','{runtime['subject_digest']}',
 '{DIGITS['runtime_manifest']}','{DIGITS['runtime_config']}','{DIGITS['extension_subject']}',
 '{DIGITS['extension_manifest']}','{DIGITS['extension_config']}','{DIGITS['payload']}',
 '{extension_volume}','{qualification}','{DIGITS['bridge']}',{sql_literal(manifest['addons'])}::jsonb,
 now(),now(),now(),'{{"workspace_fixture":true}}'::jsonb)
on conflict(runtime_key,slot) do nothing;
"""
    psql(workspace, insert)

    tenant = uuid.uuid4()
    owner = uuid.uuid4()
    database = uuid.uuid4()
    service = uuid.uuid4()
    database_ref = f"mb_{tenant.hex}"
    host = f"fixture-{tenant.hex[:12]}.{workspace}.makersbrain.net"
    docs_host = f"docs-{tenant.hex[:12]}.{workspace}.makersbrain.net"
    seed = f"""
insert into control.users(id,email) values('{owner}','owner+{tenant.hex[:12]}@example.test');
insert into control.workshops(id,slug,display_name,country_code,time_zone)
 values('{tenant}','recovery-{tenant.hex[:12]}','Workspace recovery fixture','FR','Europe/Paris');
insert into control.memberships(workshop_id,user_id,role) values('{tenant}','{owner}','owner');
insert into control.odoo_databases(id,workshop_id,kind,database_ref,public_hostname,label,routable)
 values('{database}','{tenant}','primary','{database_ref}','{host}','Primary fixture',true);
"""
    psql(workspace, seed)
    response = driver(
        workspace,
        tenant,
        "provision",
        {
            "database_ref": database_ref,
            "public_hostname": host,
            "paperless_enabled": True,
            "paperless_hostname": docs_host,
        },
        f"workspace-fixture-provision:{tenant}",
    )
    paperless = response.get("paperless")
    if not isinstance(paperless, dict):
        raise SystemExit("driver did not provision the Paperless fixture")
    finalize = f"""
insert into control.service_instances(id,workshop_id,service,base_url,secret_ref,release_id,applied_epoch,health,last_observed_at)
 values('{service}','{tenant}','odoo','http://odoo:8069','docker/{tenant}/odoo','{release}',1,'ready',now());
update control.odoo_databases set service_instance_id='{service}',state='ready' where id='{database}';
update control.workshops set status='active' where id='{tenant}';
insert into control.workshop_modules(
 workshop_id,module_key,state,requested_by,enabled_at,application_release_id,resolved_implementation)
values('{tenant}','documents','enabled','{owner}',now(),'{release}','{{"service":"paperless"}}'::jsonb)
on conflict(workshop_id,module_key) do nothing;
"""
    psql(workspace, finalize)
    save_state(workspace, {
        "schema": "makersbrain.workspace-recovery-acceptance.v1",
        "workspace": workspace,
        "workshop_id": str(tenant),
        "owner_id": str(owner),
        "database_id": str(database),
        "database_ref": database_ref,
        "public_hostname": host,
        "paperless_hostname": docs_host,
        "release_id": release,
    })
    print(f"prepared synthetic recovery tenant {tenant} in {workspace}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command", choices=("prepare", "seed", "backup", "rehearse", "mutate", "restore", "verify")
    )
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--new", action="store_true", help="create a new recovery point for backup")
    args = parser.parse_args()
    if not WORKSPACE_RE.fullmatch(args.workspace):
        parser.error("workspace must be dev1 through dev4")
    if args.command == "prepare":
        prepare(args.workspace)
    elif args.command == "seed":
        seed(args.workspace)
    elif args.command == "backup":
        backup(args.workspace, args.new)
    elif args.command == "rehearse":
        rehearse(args.workspace)
    elif args.command == "mutate":
        mutate(args.workspace)
    elif args.command == "restore":
        restore(args.workspace)
    elif args.command == "verify":
        verify(args.workspace)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as error:
        if error.stdout:
            sys.stderr.write(error.stdout)
        raise
