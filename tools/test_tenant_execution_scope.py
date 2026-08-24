#!/usr/bin/env python3
"""Fail closed when API workshop transactions bypass the typed tenant seam."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


persistence = (ROOT / "src/persistence.rs").read_text()
api = (ROOT / "src/api.rs").read_text()
config = (ROOT / "src/config.rs").read_text()
workshops = (ROOT / "src/api/workshops.rs").read_text()

require("pub struct TenantStore" in persistence, "TenantStore is missing")
tenant_impl = persistence.split("impl TenantStore", 1)[1].split("impl<'a> WorkshopTransaction", 1)[0]
require("pub fn pool(" not in tenant_impl, "TenantStore must not expose its bare pool")
require(
    "select set_config('control.workshop_id',$1,true)" in persistence,
    "workshop context must be transaction-local",
)
require("pub tenant_store: TenantStore" in api, "AppState must own a distinct tenant pool")
require(
    "CONTROL_TENANT_DATABASE_URL" in config and "distinct_database_login" in config,
    "API configuration must require a distinct tenant database login",
)

api_sources = [ROOT / "src/api.rs", *sorted((ROOT / "src/api").glob("*.rs"))]
checked = 0
for path in api_sources:
    lines = path.read_text().splitlines()
    for index, line in enumerate(lines):
        if "revalidate_workshop_scope(" not in line or line.lstrip().startswith("async fn"):
            continue
        window = "\n".join(lines[max(0, index - 12) : index + 1])
        require(
            re.search(r"tenant_store\s*\.begin\(", window) is not None,
            f"{path.relative_to(ROOT)}:{index + 1}: workshop mutation lacks a scoped tenant transaction",
        )
        require(
            "state.store.begin()" not in window,
            f"{path.relative_to(ROOT)}:{index + 1}: workshop mutation uses the fleet/platform pool",
        )
        checked += 1

require(checked >= 20, "unexpectedly few workshop transaction boundaries were checked")

accept = workshops.split("pub(super) async fn accept_ownership_transfer", 1)[1]
accept = accept.split("\n}\n", 1)[0]
platform_lookup = accept.find("fetch_optional(state.store.pool())")
tenant_begin = accept.find("state.tenant_store.begin(discovered.0)")
locked_reread = accept.find("for update of t")
require(
    0 <= platform_lookup < tenant_begin < locked_reread,
    "ownership-transfer acceptance must discover through platform scope then lock in tenant scope",
)

print(f"{checked} workshop mutations use transaction-local tenant execution scopes")
