#!/usr/bin/env python3
"""Enable, verify, or lower the staging cutover database write fence."""

from __future__ import annotations

import argparse
import subprocess


RUNTIME_ROLES = (
    "control_api",
    "control_membership_worker",
    "control_provisioning_worker",
    "control_invoice_worker",
    "control_inventory_worker",
    "control_email_worker",
    "control_reconciliation_worker",
    "control_lifecycle_worker",
    "control_backup_scheduler",
    "control_driver_ledger",
    "control_release_worker",
    "control_privacy_worker",
    "rauthy",
    "odoo",
)


def sql(action: str) -> str:
    if action == "status":
        names = ",".join(f"'{role}'" for role in RUNTIME_ROLES)
        return (
            "select rolname, coalesce(array_to_string(rolconfig, ','), '') "
            f"from pg_roles where rolname in ({names}) order by rolname;"
        )
    if action == "verify":
        names = ",".join(f"'{role}'" for role in RUNTIME_ROLES)
        return f"""
do $$
declare
  missing text;
begin
  select string_agg(rolname, ', ' order by rolname) into missing
    from pg_roles
   where rolname in ({names})
     and not (coalesce(rolconfig, array[]::text[]) @>
              array['default_transaction_read_only=on']);
  if missing is not null then
    raise exception 'runtime roles are not write-fenced: %', missing;
  end if;
  if (select count(*) from pg_roles where rolname in ({names})) <> {len(RUNTIME_ROLES)} then
    raise exception 'one or more required runtime roles do not exist';
  end if;
end
$$;
""".strip()
    setting = "set default_transaction_read_only = on" if action == "enable" else "reset default_transaction_read_only"
    statements = [f'alter role "{role}" {setting};' for role in RUNTIME_ROLES]
    if action == "enable":
        names = ",".join(f"'{role}'" for role in RUNTIME_ROLES)
        statements.append(
            "select pg_terminate_backend(pid) from pg_stat_activity "
            f"where usename in ({names}) and pid <> pg_backend_pid();"
        )
    return "\n".join(statements)


def run(action: str) -> None:
    command = [
        "podman",
        "exec",
        "-i",
        "makersbrain-postgres",
        "sh",
        "-ec",
        "PGPASSWORD=$(cat /run/secrets/postgres_superuser_password) "
        "exec psql --set=ON_ERROR_STOP=1 --username postgres --dbname postgres",
    ]
    subprocess.run(command, input=sql(action), text=True, check=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("enable", "status", "verify", "disable"))
    args = parser.parse_args()
    run(args.action)


if __name__ == "__main__":
    main()
