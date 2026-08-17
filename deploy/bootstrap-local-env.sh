#!/bin/sh
set -eu

target=${1:-deploy/.env}
if [ -e "$target" ]; then
  echo "$target already exists; refusing to overwrite local credentials" >&2
  exit 1
fi
command -v openssl >/dev/null 2>&1 || { echo "openssl is required" >&2; exit 1; }

random_hex() { openssl rand -hex 32; }
secret_ref() {
  printf '@/run/secrets/%s' "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
}

target_dir=$(dirname "$target")
runtime_dir="$target_dir/secrets/runtime"
if [ -e "$runtime_dir" ]; then
  echo "$runtime_dir already exists; refusing to overwrite local credentials" >&2
  exit 1
fi
temporary="${target}.tmp"
runtime_temporary="${runtime_dir}.tmp.$$"
cleanup() {
  rm -f "$temporary"
  rm -rf "$runtime_temporary"
}
trap cleanup EXIT HUP INT TERM
umask 077
mkdir -p "$runtime_temporary"

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

control_password=$(random_hex)
control_api_password=$(random_hex)
control_membership_password=$(random_hex)
control_provisioning_password=$(random_hex)
control_invoice_password=$(random_hex)
control_inventory_password=$(random_hex)
control_email_password=$(random_hex)
control_reconciliation_password=$(random_hex)
control_lifecycle_password=$(random_hex)
control_backup_password=$(random_hex)
control_driver_password=$(random_hex)
control_release_password=$(random_hex)
control_privacy_password=$(random_hex)
postgres_superuser_password=$(random_hex)
rauthy_password=$(random_hex)
odoo_password=$(random_hex)
enc_active=$(date -u +%Y-%m-%d)
enc_key=$(openssl rand -base64 32 | tr -d '\n')
admin_password=$(random_hex)
hql_secret_raft=$(random_hex)
hql_secret_api=$(random_hex)
privacy_lookup_key=$(openssl rand -base64 32 | tr -d '\n')
privacy_export_key=$(openssl rand -base64 32 | tr -d '\n')
source_commit=$(git rev-parse --verify HEAD 2>/dev/null || printf 'unreleased')

write_secret CONTROL_POSTGRES_PASSWORD "$control_password"
write_secret CONTROL_API_POSTGRES_PASSWORD "$control_api_password"
write_secret CONTROL_MEMBERSHIP_POSTGRES_PASSWORD "$control_membership_password"
write_secret CONTROL_PROVISIONING_POSTGRES_PASSWORD "$control_provisioning_password"
write_secret CONTROL_INVOICE_POSTGRES_PASSWORD "$control_invoice_password"
write_secret CONTROL_INVENTORY_POSTGRES_PASSWORD "$control_inventory_password"
write_secret CONTROL_EMAIL_POSTGRES_PASSWORD "$control_email_password"
write_secret CONTROL_RECONCILIATION_POSTGRES_PASSWORD "$control_reconciliation_password"
write_secret CONTROL_LIFECYCLE_POSTGRES_PASSWORD "$control_lifecycle_password"
write_secret CONTROL_BACKUP_POSTGRES_PASSWORD "$control_backup_password"
write_secret CONTROL_DRIVER_POSTGRES_PASSWORD "$control_driver_password"
write_secret CONTROL_RELEASE_POSTGRES_PASSWORD "$control_release_password"
write_secret CONTROL_PRIVACY_POSTGRES_PASSWORD "$control_privacy_password"
write_secret POSTGRES_SUPERUSER_PASSWORD "$postgres_superuser_password"
write_secret RAUTHY_POSTGRES_PASSWORD "$rauthy_password"
write_secret ODOO_POSTGRES_PASSWORD "$odoo_password"
write_secret RAUTHY_ENC_KEYS "$enc_active/$enc_key"
write_secret RAUTHY_BOOTSTRAP_ADMIN_PASSWORD "$admin_password"
write_secret RAUTHY_HQL_SECRET_RAFT "$hql_secret_raft"
write_secret RAUTHY_HQL_SECRET_API "$hql_secret_api"
write_secret CONTROL_INTERNAL_TOKEN "$(random_hex)"
write_secret CONTROL_METRICS_TOKEN "$(random_hex)"
write_secret CONTROL_MAIL_EVENT_TOKEN "$(random_hex)"
write_secret CONTROL_RELEASE_PUBLISH_TOKEN "$(random_hex)"
write_secret ODOO_BRIDGE_TOKEN "$(random_hex)"
write_secret DOCUMENT_EXTRACTION_TOKEN "$(random_hex)"
write_secret CONTROL_RAUTHY_ADMIN_KEY "makersbrain-runtime\$$(random_hex)"
write_secret CONTROL_RAUTHY_DEPLOYMENT_KEY "makersbrain-deployment\$$(random_hex)"
write_secret MAIL_WEBHOOK_TOKEN "$(random_hex)"
write_secret DEPLOYMENT_DRIVER_TOKEN "$(random_hex)"
write_secret PRIVACY_DRIVER_TOKEN "$(random_hex)"
write_secret CONTROL_PRIVACY_LOOKUP_KEY "$privacy_lookup_key"
write_secret CONTROL_PRIVACY_EXPORT_KEY "$privacy_export_key"

# Optional provider and backup capabilities use the same mounted-file boundary.
# Empty files keep those capabilities disabled without putting placeholders in
# a rendered Compose model.
for optional_secret in \
  AZURE_DOCUMENT_KEY INVENTORY_OPENAI_KEY INVENTORY_AZURE_MULTIMODAL_KEY \
  INVENTORY_GEMINI_KEY INVENTORY_CLAUDE_KEY INVENTORY_VISION_KEY \
  INVENTORY_UPCITEMDB_KEY BACKUP_S3_ACCESS_KEY_ID \
  BACKUP_S3_SECRET_ACCESS_KEY RESTORE_S3_ACCESS_KEY_ID \
  RESTORE_S3_SECRET_ACCESS_KEY BACKUP_AGE_RECIPIENT CLOUDFLARE_TUNNEL_TOKEN \
  CONTROL_CLOUDFLARE_API_TOKEN CONTROL_MAIL_SCW_SECRET_KEY
do
  eval "configured=\${$optional_secret-}"
  write_secret "$optional_secret" "$configured"
done

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
  '[cluster]' \
  "secret_raft = \"$hql_secret_raft\"" \
  "secret_api = \"$hql_secret_api\"" \
  '[database]' \
  "pg_password = \"$rauthy_password\"" \
  '[bootstrap]' \
  "password_plain = \"$admin_password\"" \
  '[encryption]' \
  "keys = [\"$enc_active/$enc_key\"]" \
  "key_active = \"$enc_active\"")
write_named_secret rauthy_config.toml "$rauthy_config"

invitation_dir="$target_dir/secrets/invitation"
invitation_private="$invitation_dir/private.pem"
invitation_private_keys="$invitation_dir/private-keys.json"
invitation_public="$invitation_dir/public-keys.json"
invitation_key_id="local-$enc_active"
mkdir -p "$invitation_dir"
if [ ! -e "$invitation_private" ]; then
  openssl genpkey -algorithm ED25519 -out "$invitation_private"
fi
public_der=$(openssl pkey -in "$invitation_private" -pubout -outform DER | openssl base64 -A)
private_der=$(openssl pkey -in "$invitation_private" -outform DER | openssl base64 -A)
printf '{"keys":{"%s":"%s"}}\n' "$invitation_key_id" "$private_der" > "$invitation_private_keys"
printf '{"keys":{"%s":"%s"}}\n' "$invitation_key_id" "$public_der" > "$invitation_public"
chmod 0600 "$invitation_private" "$invitation_private_keys"
chmod 0644 "$invitation_public"

{
  printf '%s\n' \
    "CONTROL_POSTGRES_PASSWORD=$(secret_ref CONTROL_POSTGRES_PASSWORD)" \
    "CONTROL_API_POSTGRES_PASSWORD=$(secret_ref CONTROL_API_POSTGRES_PASSWORD)" \
    "CONTROL_MEMBERSHIP_POSTGRES_PASSWORD=$(secret_ref CONTROL_MEMBERSHIP_POSTGRES_PASSWORD)" \
    "CONTROL_PROVISIONING_POSTGRES_PASSWORD=$(secret_ref CONTROL_PROVISIONING_POSTGRES_PASSWORD)" \
    "CONTROL_INVOICE_POSTGRES_PASSWORD=$(secret_ref CONTROL_INVOICE_POSTGRES_PASSWORD)" \
    "CONTROL_INVENTORY_POSTGRES_PASSWORD=$(secret_ref CONTROL_INVENTORY_POSTGRES_PASSWORD)" \
    "CONTROL_EMAIL_POSTGRES_PASSWORD=$(secret_ref CONTROL_EMAIL_POSTGRES_PASSWORD)" \
    "CONTROL_RECONCILIATION_POSTGRES_PASSWORD=$(secret_ref CONTROL_RECONCILIATION_POSTGRES_PASSWORD)" \
    "CONTROL_LIFECYCLE_POSTGRES_PASSWORD=$(secret_ref CONTROL_LIFECYCLE_POSTGRES_PASSWORD)" \
    "CONTROL_BACKUP_POSTGRES_PASSWORD=$(secret_ref CONTROL_BACKUP_POSTGRES_PASSWORD)" \
    "CONTROL_DRIVER_POSTGRES_PASSWORD=$(secret_ref CONTROL_DRIVER_POSTGRES_PASSWORD)" \
    "CONTROL_RELEASE_POSTGRES_PASSWORD=$(secret_ref CONTROL_RELEASE_POSTGRES_PASSWORD)" \
    "CONTROL_PRIVACY_POSTGRES_PASSWORD=$(secret_ref CONTROL_PRIVACY_POSTGRES_PASSWORD)" \
    "CONTROL_PRIVACY_LOOKUP_KEY_ID=local-privacy-$enc_active" \
    "CONTROL_PRIVACY_LOOKUP_KEY=$(secret_ref CONTROL_PRIVACY_LOOKUP_KEY)" \
    "CONTROL_PRIVACY_EXPORT_KEY_ID=local-export-$enc_active" \
    "CONTROL_PRIVACY_EXPORT_KEY=$(secret_ref CONTROL_PRIVACY_EXPORT_KEY)" \
    "CONTROL_API_PORT=8180" \
    "CONTROL_WEB_PORT=4175" \
    "CONTROL_DATA_MODE=synthetic" \
    "RAUTHY_HTTP_PORT=8093" \
    "ODOO_HTTP_PORT=8269" \
    "RAUTHY_HTTPS_PORT=18443" \
    "PUBLIC_DOMAIN=dev1.makersbrain.net" \
    "CLOUDFLARE_TUNNEL_TOKEN=$(secret_ref CLOUDFLARE_TUNNEL_TOKEN)" \
    "CONTROL_CLOUDFLARE_API_TOKEN=$(secret_ref CONTROL_CLOUDFLARE_API_TOKEN)" \
    "CONTROL_CLOUDFLARE_ZONE_ID=${CONTROL_CLOUDFLARE_ZONE_ID:-}" \
    "CONTROL_MAIL_SCW_PROJECT_ID=${CONTROL_MAIL_SCW_PROJECT_ID:-}" \
    "CONTROL_MAIL_SCW_SECRET_KEY=$(secret_ref CONTROL_MAIL_SCW_SECRET_KEY)" \
    "CONTROL_MAIL_SNS_TOPIC_ARN=${CONTROL_MAIL_SNS_TOPIC_ARN:-}" \
    "RAUTHY_POSTGRES_PASSWORD=$(secret_ref RAUTHY_POSTGRES_PASSWORD)" \
    "ODOO_POSTGRES_PASSWORD=$(secret_ref ODOO_POSTGRES_PASSWORD)" \
    "RAUTHY_ENC_KEYS=$(secret_ref RAUTHY_ENC_KEYS)" \
    "RAUTHY_ENC_KEY_ACTIVE=$enc_active" \
    "RAUTHY_BOOTSTRAP_ADMIN_EMAIL=owner@example.test" \
    "CONTROL_OPERATOR_EMAILS=owner@example.test" \
    "RAUTHY_BOOTSTRAP_ADMIN_PASSWORD=$(secret_ref RAUTHY_BOOTSTRAP_ADMIN_PASSWORD)" \
    "RAUTHY_HQL_SECRET_RAFT=$(secret_ref RAUTHY_HQL_SECRET_RAFT)" \
    "RAUTHY_HQL_SECRET_API=$(secret_ref RAUTHY_HQL_SECRET_API)" \
    "CONTROL_INTERNAL_TOKEN=$(secret_ref CONTROL_INTERNAL_TOKEN)" \
    "CONTROL_METRICS_TOKEN=$(secret_ref CONTROL_METRICS_TOKEN)" \
    "CONTROL_MAIL_EVENT_TOKEN=$(secret_ref CONTROL_MAIL_EVENT_TOKEN)" \
    "CONTROL_RELEASE_PUBLISH_TOKEN=$(secret_ref CONTROL_RELEASE_PUBLISH_TOKEN)" \
    "CONTROL_RELEASE_ID=control-local-$source_commit" \
    "ODOO_BRIDGE_TOKEN=$(secret_ref ODOO_BRIDGE_TOKEN)" \
    "DOCUMENT_EXTRACTION_TOKEN=$(secret_ref DOCUMENT_EXTRACTION_TOKEN)" \
    "INVITATION_SIGNING_KEY_ID=$invitation_key_id" \
    "CONTROL_RAUTHY_ADMIN_KEY=$(secret_ref CONTROL_RAUTHY_ADMIN_KEY)" \
    "CONTROL_RAUTHY_DEPLOYMENT_KEY=$(secret_ref CONTROL_RAUTHY_DEPLOYMENT_KEY)" \
    "AZURE_DOCUMENT_ENDPOINT=${AZURE_DOCUMENT_ENDPOINT:-}" \
    "AZURE_DOCUMENT_KEY=$(secret_ref AZURE_DOCUMENT_KEY)" \
    "MAIL_WEBHOOK_URL=http://integration-fixture:8080/send" \
    "MAIL_WEBHOOK_TOKEN=$(secret_ref MAIL_WEBHOOK_TOKEN)" \
    "DEPLOYMENT_DRIVER_URL=http://docker-driver:8080" \
    "DEPLOYMENT_DRIVER_TOKEN=$(secret_ref DEPLOYMENT_DRIVER_TOKEN)" \
    "PRIVACY_DRIVER_TOKEN=$(secret_ref PRIVACY_DRIVER_TOKEN)" \
    "RELEASE_SLSA_BUILDER_ID=local-synthetic-builder"
} > "$temporary"
chmod 0600 "$temporary"
mkdir -p "$(dirname "$runtime_dir")"
mv "$runtime_temporary" "$runtime_dir"
mv "$temporary" "$target"
trap - EXIT HUP INT TERM
echo "generated $target and mounted secret files for owner@example.test"
