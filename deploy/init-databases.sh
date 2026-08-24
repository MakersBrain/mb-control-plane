#!/bin/sh
set -eu

for name in \
  CONTROL_POSTGRES_PASSWORD CONTROL_API_POSTGRES_PASSWORD \
  CONTROL_TENANT_API_POSTGRES_PASSWORD \
  CONTROL_MEMBERSHIP_POSTGRES_PASSWORD CONTROL_PROVISIONING_POSTGRES_PASSWORD \
  CONTROL_INVOICE_POSTGRES_PASSWORD CONTROL_INVENTORY_POSTGRES_PASSWORD \
  CONTROL_EMAIL_POSTGRES_PASSWORD CONTROL_RECONCILIATION_POSTGRES_PASSWORD \
  CONTROL_LIFECYCLE_POSTGRES_PASSWORD CONTROL_BACKUP_POSTGRES_PASSWORD \
  CONTROL_DRIVER_POSTGRES_PASSWORD CONTROL_RELEASE_POSTGRES_PASSWORD \
  CONTROL_PRIVACY_POSTGRES_PASSWORD RAUTHY_POSTGRES_PASSWORD ODOO_POSTGRES_PASSWORD
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

psql --set=ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=control_password="$CONTROL_POSTGRES_PASSWORD" \
  --set=control_api_password="$CONTROL_API_POSTGRES_PASSWORD" \
  --set=control_tenant_api_password="$CONTROL_TENANT_API_POSTGRES_PASSWORD" \
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
  --set=control_privacy_password="$CONTROL_PRIVACY_POSTGRES_PASSWORD" \
  --set=rauthy_password="$RAUTHY_POSTGRES_PASSWORD" \
  --set=odoo_password="$ODOO_POSTGRES_PASSWORD" <<'SQL'
create role control login password :'control_password';
create role control_runtime_read nologin;
create role control_api login password :'control_api_password' in role control_runtime_read;
create role control_tenant_api login password :'control_tenant_api_password' in role control_runtime_read;
create role control_membership_worker login password :'control_membership_password' in role control_runtime_read;
create role control_provisioning_worker login password :'control_provisioning_password' in role control_runtime_read;
create role control_invoice_worker login password :'control_invoice_password' in role control_runtime_read;
create role control_inventory_worker login password :'control_inventory_password' in role control_runtime_read;
create role control_email_worker login password :'control_email_password' in role control_runtime_read;
create role control_reconciliation_worker login password :'control_reconciliation_password' in role control_runtime_read;
create role control_lifecycle_worker login password :'control_lifecycle_password' in role control_runtime_read;
create role control_backup_scheduler login password :'control_backup_password' in role control_runtime_read;
create role control_driver_ledger login password :'control_driver_password' in role control_runtime_read;
create role control_release_worker login password :'control_release_password' in role control_runtime_read;
create role control_privacy_worker login password :'control_privacy_password' in role control_runtime_read;
create role rauthy login password :'rauthy_password';
create role odoo login createdb password :'odoo_password';
create database mb_control owner control;
create database rauthy owner rauthy;
revoke all on database mb_control from public;
grant connect on database mb_control to control_runtime_read;
revoke all on database rauthy from public;
\connect mb_control
revoke create on schema public from public;
SQL
