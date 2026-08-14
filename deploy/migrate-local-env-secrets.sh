#!/bin/sh
set -eu

if [ "${1:-}" != "--apply" ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 --apply [path/to/.env]" >&2
  exit 2
fi
target=${2:-deploy/.env}
[ -f "$target" ] || { echo "$target is missing" >&2; exit 1; }
target_dir=$(dirname "$target")
runtime_dir="$target_dir/secrets/runtime"
[ ! -e "$runtime_dir" ] || { echo "$runtime_dir already exists; refusing partial migration" >&2; exit 1; }

set -a
. "$target"
set +a
umask 077
runtime_temporary="${runtime_dir}.tmp.$$"
environment_temporary="${target}.tmp.$$"
cleanup() {
  rm -f "$environment_temporary"
  rm -rf "$runtime_temporary"
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$runtime_temporary"

read_value() {
  name=$1
  required_value=$2
  eval "value=\${$name-}"
  case "$value" in
    @*) echo "$name is already a secret reference; refusing mixed migration" >&2; exit 1;;
    '')
      if [ "$required_value" = required ]; then
        echo "$name is required for migration" >&2
        exit 1
      fi
      ;;
  esac
  printf '%s' "$value"
}
write_secret() {
  name=$1
  value=$2
  file=$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')
  printf '%s' "$value" > "$runtime_temporary/$file"
  chmod 0444 "$runtime_temporary/$file"
}
write_named_secret() {
  file=$1
  value=$2
  printf '%s' "$value" > "$runtime_temporary/$file"
  chmod 0444 "$runtime_temporary/$file"
}

control_password=$(read_value CONTROL_POSTGRES_PASSWORD required)
control_api_password=$(read_value CONTROL_API_POSTGRES_PASSWORD required)
control_membership_password=$(read_value CONTROL_MEMBERSHIP_POSTGRES_PASSWORD required)
control_provisioning_password=$(read_value CONTROL_PROVISIONING_POSTGRES_PASSWORD required)
control_invoice_password=$(read_value CONTROL_INVOICE_POSTGRES_PASSWORD required)
control_inventory_password=$(read_value CONTROL_INVENTORY_POSTGRES_PASSWORD required)
control_email_password=$(read_value CONTROL_EMAIL_POSTGRES_PASSWORD required)
control_reconciliation_password=$(read_value CONTROL_RECONCILIATION_POSTGRES_PASSWORD required)
control_lifecycle_password=$(read_value CONTROL_LIFECYCLE_POSTGRES_PASSWORD required)
control_backup_password=$(read_value CONTROL_BACKUP_POSTGRES_PASSWORD required)
control_driver_password=$(read_value CONTROL_DRIVER_POSTGRES_PASSWORD required)
control_release_password=$(read_value CONTROL_RELEASE_POSTGRES_PASSWORD required)
control_privacy_password=$(read_value CONTROL_PRIVACY_POSTGRES_PASSWORD required)
rauthy_password=$(read_value RAUTHY_POSTGRES_PASSWORD required)
odoo_password=$(read_value ODOO_POSTGRES_PASSWORD required)
rauthy_enc_keys=$(read_value RAUTHY_ENC_KEYS required)
rauthy_admin_password=$(read_value RAUTHY_BOOTSTRAP_ADMIN_PASSWORD required)
rauthy_hql_raft=$(read_value RAUTHY_HQL_SECRET_RAFT required)
rauthy_hql_api=$(read_value RAUTHY_HQL_SECRET_API required)

required_secrets="CONTROL_POSTGRES_PASSWORD CONTROL_API_POSTGRES_PASSWORD CONTROL_MEMBERSHIP_POSTGRES_PASSWORD CONTROL_PROVISIONING_POSTGRES_PASSWORD CONTROL_INVOICE_POSTGRES_PASSWORD CONTROL_INVENTORY_POSTGRES_PASSWORD CONTROL_EMAIL_POSTGRES_PASSWORD CONTROL_RECONCILIATION_POSTGRES_PASSWORD CONTROL_LIFECYCLE_POSTGRES_PASSWORD CONTROL_BACKUP_POSTGRES_PASSWORD CONTROL_DRIVER_POSTGRES_PASSWORD CONTROL_RELEASE_POSTGRES_PASSWORD CONTROL_PRIVACY_POSTGRES_PASSWORD RAUTHY_POSTGRES_PASSWORD ODOO_POSTGRES_PASSWORD RAUTHY_ENC_KEYS RAUTHY_BOOTSTRAP_ADMIN_PASSWORD RAUTHY_HQL_SECRET_RAFT RAUTHY_HQL_SECRET_API CONTROL_INTERNAL_TOKEN CONTROL_RELEASE_PUBLISH_TOKEN ODOO_BRIDGE_TOKEN DOCUMENT_EXTRACTION_TOKEN CONTROL_RAUTHY_ADMIN_KEY CONTROL_RAUTHY_DEPLOYMENT_KEY MAIL_WEBHOOK_TOKEN DEPLOYMENT_DRIVER_TOKEN PRIVACY_DRIVER_TOKEN CONTROL_PRIVACY_LOOKUP_KEY CONTROL_PRIVACY_EXPORT_KEY"
optional_secrets="AZURE_DOCUMENT_KEY INVENTORY_OPENAI_KEY INVENTORY_AZURE_MULTIMODAL_KEY INVENTORY_GEMINI_KEY INVENTORY_CLAUDE_KEY INVENTORY_VISION_KEY INVENTORY_UPCITEMDB_KEY BACKUP_S3_ACCESS_KEY_ID BACKUP_S3_SECRET_ACCESS_KEY RESTORE_S3_ACCESS_KEY_ID RESTORE_S3_SECRET_ACCESS_KEY BACKUP_AGE_RECIPIENT CLOUDFLARE_TUNNEL_TOKEN"
for name in $required_secrets; do
  write_secret "$name" "$(read_value "$name" required)"
done
for name in $optional_secrets; do
  write_secret "$name" "$(read_value "$name" optional)"
done

# The legacy topology used a fixed local superuser password. Preserve that
# development-only value while moving it out of rendered configuration.
postgres_superuser_password=${POSTGRES_SUPERUSER_PASSWORD:-local-superuser-not-published}
write_secret POSTGRES_SUPERUSER_PASSWORD "$postgres_superuser_password"
write_named_secret control_database_url "postgresql://control:$control_password@postgres:5432/makersbrain_control"
write_named_secret control_api_database_url "postgresql://control_api:$control_api_password@postgres:5432/makersbrain_control"
write_named_secret control_membership_database_url "postgresql://control_membership_worker:$control_membership_password@postgres:5432/makersbrain_control"
write_named_secret control_provisioning_database_url "postgresql://control_provisioning_worker:$control_provisioning_password@postgres:5432/makersbrain_control"
write_named_secret control_invoice_database_url "postgresql://control_invoice_worker:$control_invoice_password@postgres:5432/makersbrain_control"
write_named_secret control_inventory_database_url "postgresql://control_inventory_worker:$control_inventory_password@postgres:5432/makersbrain_control"
write_named_secret control_email_database_url "postgresql://control_email_worker:$control_email_password@postgres:5432/makersbrain_control"
write_named_secret control_reconciliation_database_url "postgresql://control_reconciliation_worker:$control_reconciliation_password@postgres:5432/makersbrain_control"
write_named_secret control_lifecycle_database_url "postgresql://control_lifecycle_worker:$control_lifecycle_password@postgres:5432/makersbrain_control"
write_named_secret control_backup_database_url "postgresql://control_backup_scheduler:$control_backup_password@postgres:5432/makersbrain_control"
write_named_secret control_driver_database_url "postgresql://control_driver_ledger:$control_driver_password@postgres:5432/makersbrain_control"
write_named_secret control_release_database_url "postgresql://control_release_worker:$control_release_password@postgres:5432/makersbrain_control"
write_named_secret control_privacy_database_url "postgresql://control_privacy_worker:$control_privacy_password@postgres:5432/makersbrain_control"
write_named_secret postgres_admin_database_url "postgresql://postgres:$postgres_superuser_password@postgres:5432/postgres"
rauthy_config=$(printf '%s\n' \
  '[cluster]' "secret_raft = \"$rauthy_hql_raft\"" "secret_api = \"$rauthy_hql_api\"" \
  '[database]' "pg_password = \"$rauthy_password\"" \
  '[bootstrap]' "password_plain = \"$rauthy_admin_password\"" \
  '[encryption]' "keys = [\"$rauthy_enc_keys\"]" \
  "key_active = \"${RAUTHY_ENC_KEY_ACTIVE:?RAUTHY_ENC_KEY_ACTIVE is required}\"")
write_named_secret rauthy_config.toml "$rauthy_config"

all_secret_names="$required_secrets $optional_secrets"
while IFS= read -r line || [ -n "$line" ]; do
  name=${line%%=*}
  case " $all_secret_names " in
    *" $name "*)
      file=$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')
      printf '%s=@/run/secrets/%s\n' "$name" "$file"
      ;;
    *) printf '%s\n' "$line" ;;
  esac
done < "$target" > "$environment_temporary"
chmod 0600 "$environment_temporary"
mkdir -p "$(dirname "$runtime_dir")"
mv "$runtime_temporary" "$runtime_dir"
mv "$environment_temporary" "$target"
trap - EXIT HUP INT TERM
echo "migrated $target to mounted secret-file references"
