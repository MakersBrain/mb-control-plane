#!/usr/bin/env python3
"""Reject human-API tenant-child mutations without a workshop WHERE predicate.

This is a deliberately narrow source regression gate, not proof of database
isolation. Cross-tenant runtime-role tests remain the authoritative phase-2
gate.
"""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
API_FILES = (
    "src/api.rs",
    "src/api/workshops.rs",
    "src/api/domains.rs",
    "src/api/email_domains.rs",
    "src/api/carrier_secrets.rs",
    "src/api/recovery.rs",
    "src/api/webshop.rs",
    "src/api/smtp.rs",
)
TENANT_CHILD_TABLES = (
    "carrier_secrets",
    "entitlements",
    "erasure_tombstones",
    "invitations",
    "membership_targets",
    "memberships",
    "odoo_databases",
    "outbox",
    "ownership_transfers",
    "service_instances",
    "tenant_release_adoptions",
    "webshop_domains",
    "webshop_email_domains",
    "webshop_onboarding",
    "workshop_modules",
    "workshop_recovery_points",
)
RUST_STRING = re.compile(r'"((?:\\.|[^"\\])*)"', re.DOTALL)
MUTATION = re.compile(
    rf"\b(update|delete\s+from)\s+control\.({'|'.join(TENANT_CHILD_TABLES)})\b",
    re.IGNORECASE,
)
WORKSHOP_PREDICATE = re.compile(r"\b(?:[a-z][a-z0-9_]*\.)?workshop_id\s*=", re.IGNORECASE)


def line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def find_violations(relative: str, source: str) -> list[str]:
    failures: list[str] = []
    for literal in RUST_STRING.finditer(source):
        sql = literal.group(1)
        for mutation in MUTATION.finditer(sql):
            predicate_start = sql.lower().find("where", mutation.end())
            predicate = "" if predicate_start < 0 else sql[predicate_start:]
            if WORKSHOP_PREDICATE.search(predicate):
                continue
            failures.append(
                f"{relative}:{line_number(source, literal.start())}: "
                f"mutation of control.{mutation.group(2)} lacks a workshop_id WHERE predicate"
            )
    return failures


def main() -> int:
    unsafe_fixtures = (
        'sqlx::query("update control.webshop_domains set state=\'active\' where id=$1")',
        'sqlx::query("update control.webshop_domains set workshop_id=$2 where id=$1")',
    )
    if any(not find_violations("src/api/domains.rs", fixture) for fixture in unsafe_fixtures):
        raise AssertionError("tenant mutation detector accepted an unsafe fixture")
    safe_fixture = 'sqlx::query("delete from control.webshop_domains where id=$1 and workshop_id=$2")'
    if find_violations("src/api/domains.rs", safe_fixture):
        raise AssertionError("tenant mutation detector rejected a scoped fixture")

    domains = (ROOT / "src/api/domains.rs").read_text(encoding="utf-8")
    if "on conflict(hostname) do update" in domains.lower():
        raise AssertionError(
            "webshop hostname claims must not transfer a disconnected row across workshops"
        )
    if "workshop_id=excluded.workshop_id" in domains.replace(" ", "").lower():
        raise AssertionError("webshop hostname claims must keep historical ownership immutable")
    if "control.claim_webshop_domain($1,$2,$3,$4,$5,$6,$7)" not in domains:
        raise AssertionError("hostname claims must use the stable scoped database capability")
    if 'outcome == "conflict"' not in domains or "This hostname is already claimed" not in domains:
        raise AssertionError("hostname claims must preserve the public conflict response")

    webshop = (ROOT / "src/api/webshop.rs").read_text(encoding="utf-8")
    domain_dashboard_read = webshop.split(
        "let mut domain_tx = state.tenant_store.begin(workshop).await?;", 1
    )[-1].split("if domains.0 > 0", 1)[0]
    if "from control.webshop_domains" not in domain_dashboard_read or ".fetch_one(&mut *domain_tx)" not in domain_dashboard_read:
        raise AssertionError("webshop dashboard domain reads must use a workshop transaction")

    failures: list[str] = []
    for relative in API_FILES:
        source = (ROOT / relative).read_text(encoding="utf-8")
        failures.extend(find_violations(relative, source))
    if failures:
        print("tenant query scope violations:")
        print("\n".join(f"- {failure}" for failure in failures))
        return 1
    print("human API tenant-child string-literal mutations include workshop_id predicates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
