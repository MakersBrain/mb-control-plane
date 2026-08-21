#!/bin/sh
set -eu

for name in \
  POSTGRES_SUPERUSER_PASSWORD CONTROL_API_POSTGRES_PASSWORD \
  CONTROL_MEMBERSHIP_POSTGRES_PASSWORD CONTROL_PROVISIONING_POSTGRES_PASSWORD \
  CONTROL_INVOICE_POSTGRES_PASSWORD CONTROL_INVENTORY_POSTGRES_PASSWORD \
  CONTROL_EMAIL_POSTGRES_PASSWORD CONTROL_RECONCILIATION_POSTGRES_PASSWORD \
  CONTROL_LIFECYCLE_POSTGRES_PASSWORD CONTROL_BACKUP_POSTGRES_PASSWORD \
  CONTROL_DRIVER_POSTGRES_PASSWORD CONTROL_RELEASE_POSTGRES_PASSWORD \
  CONTROL_PRIVACY_POSTGRES_PASSWORD
do
  eval "value=\${$name-}"
  case "$value" in
    @/run/secrets/*)
      path=${value#@}
      [ -f "$path" ] || { echo "missing secret reference for $name" >&2; exit 1; }
      value=$(cat "$path")
      export "$name=$value"
      ;;
    '') echo "$name is required" >&2; exit 1 ;;
  esac
done

export PGPASSWORD=$POSTGRES_SUPERUSER_PASSWORD
psql --set=ON_ERROR_STOP=1 --host="${PGHOST:-postgres}" --username=postgres --dbname=postgres \
  --set=control_api_password="$CONTROL_API_POSTGRES_PASSWORD" \
  --set=control_membership_password="$CONTROL_MEMBERSHIP_POSTGRES_PASSWORD" \
  --set=control_provisioning_password="$CONTROL_PROVISIONING_POSTGRES_PASSWORD" \
  --set=control_invoice_password="$CONTROL_INVOICE_POSTGRES_PASSWORD" \
  --set=control_inventory_password="$CONTROL_INVENTORY_POSTGRES_PASSWORD" \
  --set=control_email_password="$CONTROL_EMAIL_POSTGRES_PASSWORD" \
  --set=control_reconciliation_password="$CONTROL_RECONCILIATION_POSTGRES_PASSWORD" \
  --set=control_lifecycle_password="$CONTROL_LIFECYCLE_POSTGRES_PASSWORD" \
  --set=control_backup_password="$CONTROL_BACKUP_POSTGRES_PASSWORD" \
  --set=control_driver_password="$CONTROL_DRIVER_POSTGRES_PASSWORD" \
  --set=control_release_password="$CONTROL_RELEASE_POSTGRES_PASSWORD" \
  --set=control_privacy_password="$CONTROL_PRIVACY_POSTGRES_PASSWORD" <<'SQL'
select 'create role control_runtime_read nologin'
where not exists (select from pg_roles where rolname='control_runtime_read') \gexec
select format('create role %I nologin', role_name)
from unnest(array[
  'control_api','control_membership_worker','control_provisioning_worker',
  'control_invoice_worker','control_inventory_worker','control_email_worker',
  'control_reconciliation_worker','control_lifecycle_worker',
  'control_backup_scheduler','control_driver_ledger','control_release_worker',
  'control_privacy_worker'
]) role_name
where not exists (select from pg_roles where rolname=role_name) \gexec

alter role control_runtime_read nologin nosuperuser nocreatedb nocreaterole noreplication nobypassrls;
alter role control_api login nosuperuser nocreatedb nocreaterole noreplication nobypassrls password :'control_api_password';
alter role control_membership_worker login nosuperuser nocreatedb nocreaterole noreplication nobypassrls password :'control_membership_password';
alter role control_provisioning_worker login nosuperuser nocreatedb nocreaterole noreplication nobypassrls password :'control_provisioning_password';
alter role control_invoice_worker login nosuperuser nocreatedb nocreaterole noreplication nobypassrls password :'control_invoice_password';
alter role control_inventory_worker login nosuperuser nocreatedb nocreaterole noreplication nobypassrls password :'control_inventory_password';
alter role control_email_worker login nosuperuser nocreatedb nocreaterole noreplication nobypassrls password :'control_email_password';
alter role control_reconciliation_worker login nosuperuser nocreatedb nocreaterole noreplication nobypassrls password :'control_reconciliation_password';
alter role control_lifecycle_worker login nosuperuser nocreatedb nocreaterole noreplication nobypassrls password :'control_lifecycle_password';
alter role control_backup_scheduler login nosuperuser nocreatedb nocreaterole noreplication nobypassrls password :'control_backup_password';
alter role control_driver_ledger login nosuperuser nocreatedb nocreaterole noreplication nobypassrls password :'control_driver_password';
alter role control_release_worker login nosuperuser nocreatedb nocreaterole noreplication nobypassrls password :'control_release_password';
alter role control_privacy_worker login nosuperuser nocreatedb nocreaterole noreplication nobypassrls password :'control_privacy_password';

grant control_runtime_read to control_api,control_membership_worker,
  control_provisioning_worker,control_invoice_worker,control_inventory_worker,
  control_email_worker,control_reconciliation_worker,control_lifecycle_worker,
  control_backup_scheduler,control_driver_ledger,control_release_worker,
  control_privacy_worker;
revoke all on database mb_control from public;
grant connect on database mb_control to control_runtime_read;
SQL

echo "reconciled least-privilege control database login identities"
