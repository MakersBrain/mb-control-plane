#!/bin/sh
set -eu

: "${CONTROL_TEST_ADMIN_URL:?CONTROL_TEST_ADMIN_URL is required}"
database=control_role_matrix_test
runtime_roles="control_api control_membership_worker control_provisioning_worker control_invoice_worker control_inventory_worker control_email_worker control_reconciliation_worker control_lifecycle_worker control_backup_scheduler control_driver_ledger control_release_worker control_privacy_worker"

cleanup() {
  dropdb --if-exists --force --maintenance-db="$CONTROL_TEST_ADMIN_URL" "$database" >/dev/null 2>&1 || true
  for role in $runtime_roles; do
    psql "$CONTROL_TEST_ADMIN_URL" -v ON_ERROR_STOP=1 -c "drop role if exists $role" >/dev/null 2>&1 || true
  done
  psql "$CONTROL_TEST_ADMIN_URL" -v ON_ERROR_STOP=1 -c "drop role if exists control_runtime_read" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM
cleanup

psql "$CONTROL_TEST_ADMIN_URL" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
create role control_runtime_read nologin;
create role control_api nologin in role control_runtime_read;
create role control_membership_worker nologin in role control_runtime_read;
create role control_provisioning_worker nologin in role control_runtime_read;
create role control_invoice_worker nologin in role control_runtime_read;
create role control_inventory_worker nologin in role control_runtime_read;
create role control_email_worker nologin in role control_runtime_read;
create role control_reconciliation_worker nologin in role control_runtime_read;
create role control_lifecycle_worker nologin in role control_runtime_read;
create role control_backup_scheduler nologin in role control_runtime_read;
create role control_driver_ledger nologin in role control_runtime_read;
create role control_release_worker nologin in role control_runtime_read;
create role control_privacy_worker nologin in role control_runtime_read;
SQL

createdb --maintenance-db="$CONTROL_TEST_ADMIN_URL" "$database"
test_database_url="${CONTROL_TEST_ADMIN_URL%/*}/$database"
for migration in migrations/*.sql; do
  psql "$test_database_url" -v ON_ERROR_STOP=1 -f "$migration" >/dev/null
done

psql "$test_database_url" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
do $$
declare
  unsafe_roles integer;
begin
  select count(*) into unsafe_roles from pg_roles
  where rolname in (
    'control_api','control_membership_worker','control_provisioning_worker',
    'control_invoice_worker','control_inventory_worker','control_email_worker',
    'control_reconciliation_worker','control_lifecycle_worker',
    'control_backup_scheduler','control_driver_ledger','control_release_worker',
    'control_privacy_worker'
  ) and (rolsuper or rolcreatedb or rolcreaterole or rolreplication or rolbypassrls);
  if unsafe_roles <> 0 then raise exception 'a runtime role has administrative attributes'; end if;
  if has_schema_privilege('control_email_worker','control','CREATE') then
    raise exception 'email worker can create schema objects';
  end if;
  if not has_table_privilege('control_email_worker','control.outbox','UPDATE') then
    raise exception 'email worker lacks its outbox grant';
  end if;
  if has_table_privilege('control_email_worker','control.service_instances','SELECT') then
    raise exception 'email worker can read tenant integration references';
  end if;
  if has_table_privilege('control_email_worker','control.audit_events','UPDATE') then
    raise exception 'email worker can update audit rows';
  end if;
  if not has_table_privilege('control_api','control.audit_events','INSERT')
     or has_table_privilege('control_api','control.audit_events','DELETE') then
    raise exception 'API audit privileges are unsafe';
  end if;
  if has_table_privilege('control_api','control.data_subject_exports','SELECT')
     or not has_table_privilege('control_api','control.data_subject_export_status','SELECT')
     or not has_function_privilege('control_api','control.consume_data_subject_export(uuid,uuid)','EXECUTE')
     or not has_function_privilege('control_api','control.purge_expired_data_subject_exports()','EXECUTE') then
    raise exception 'API privacy export boundary is unsafe';
  end if;
  if not has_table_privilege('control_driver_ledger','control.deployment_driver_operations','UPDATE')
     or has_table_privilege('control_driver_ledger','control.workshops','SELECT')
     or not has_function_privilege('control_driver_ledger','control.initial_release_preparable(text,integer)','EXECUTE') then
    raise exception 'driver ledger privileges are unsafe';
  end if;
  if not has_table_privilege('control_api','control.capability_registry_entries','SELECT')
     or has_table_privilege('control_api','control.capability_registry_entries','UPDATE')
     or not has_table_privilege('control_provisioning_worker','control.capability_registry_entries','SELECT')
     or has_table_privilege('control_provisioning_worker','control.capability_registry_entries','UPDATE') then
    raise exception 'capability registry privileges are incomplete or excessive';
  end if;
  if not has_table_privilege('control_reconciliation_worker','control.tenant_release_adoptions','SELECT')
     or not has_table_privilege('control_reconciliation_worker','control.release_fleet_runs','SELECT')
     or not has_table_privilege('control_reconciliation_worker','control.workshop_modules','UPDATE')
     or has_table_privilege('control_reconciliation_worker','control.tenant_release_adoptions','UPDATE') then
    raise exception 'capability restriction reconciliation privileges are incomplete or excessive';
  end if;
  if not has_table_privilege('control_api','control.carrier_secrets','INSERT')
     or has_table_privilege('control_api','control.carrier_secrets','DELETE')
     or not has_table_privilege('control_provisioning_worker','control.carrier_secrets','UPDATE')
     or not has_table_privilege('control_reconciliation_worker','control.carrier_secrets','UPDATE')
     or not has_table_privilege('control_lifecycle_worker','control.carrier_secrets','UPDATE')
     or has_table_privilege('control_email_worker','control.carrier_secrets','SELECT') then
    raise exception 'carrier credential metadata privileges are incomplete or excessive';
  end if;
  if not has_table_privilege('control_driver_ledger','control.odoo_databases','UPDATE')
     or not has_table_privilege('control_driver_ledger','control.workshop_recovery_components','INSERT')
     or not has_table_privilege('control_driver_ledger','control.data_subject_requests','SELECT')
     or not has_table_privilege('control_driver_ledger','control.memberships','SELECT')
     or not has_table_privilege('control_driver_ledger','control.external_identities','SELECT')
     or not has_table_privilege('control_driver_ledger','control.service_instances','SELECT')
     or has_table_privilege('control_driver_ledger','control.data_subject_requests','UPDATE')
     or has_table_privilege('control_driver_ledger','control.users','SELECT') then
    raise exception 'driver lifecycle privileges are incomplete or excessive';
  end if;
  if not has_table_privilege('control_privacy_worker','control.erasure_tombstones','INSERT')
     or not has_table_privilege('control_privacy_worker','control.erasure_subject_lookups','INSERT')
     or not has_table_privilege('control_privacy_worker','control.data_subject_exports','INSERT')
     or has_table_privilege('control_privacy_worker','control.service_instances','SELECT')
     or has_table_privilege('control_privacy_worker','control.processor_approvals','UPDATE')
     or has_table_privilege('control_privacy_worker','control.audit_events','UPDATE')
     or not has_function_privilege('control_privacy_worker','control.legal_hold_applies(text,uuid,uuid[])','EXECUTE') then
    raise exception 'privacy worker privileges are incomplete or excessive';
  end if;
  if not has_table_privilege('control_lifecycle_worker','control.erasure_restore_replays','UPDATE')
     or not has_table_privilege('control_lifecycle_worker','control.erasure_subject_lookups','SELECT')
     or has_table_privilege('control_lifecycle_worker','control.data_subject_requests','UPDATE') then
    raise exception 'lifecycle erasure replay privileges are incomplete or excessive';
  end if;
  if not has_table_privilege('control_driver_ledger','control.erasure_restore_replays','SELECT')
     or has_table_privilege('control_driver_ledger','control.erasure_subject_lookups','SELECT') then
    raise exception 'driver replay fence privileges are incomplete or expose processor lookup material';
  end if;
end
$$;
SQL

echo "runtime database role matrix passed"
