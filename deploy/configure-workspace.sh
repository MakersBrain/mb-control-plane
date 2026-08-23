#!/usr/bin/env bash
# Render non-secret local configuration for one validated workspace export.

set -euo pipefail
umask 077

WORKSPACE=
SECRET_ROOT=
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
CONTROL_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
INFRA_ROOT=$(cd -- "$CONTROL_ROOT/../mb-infra" && pwd)
REGISTRY="$INFRA_ROOT/environments/development/workspaces.json"
while [ "$#" -gt 0 ]; do
  case "$1" in
  --workspace) WORKSPACE=${2:-}; shift 2 ;;
  --secret-root) SECRET_ROOT=${2:-}; shift 2 ;;
  --registry) REGISTRY=${2:-}; shift 2 ;;
  *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done
if [ -z "$WORKSPACE" ] || [ -z "$SECRET_ROOT" ]; then
  printf '%s\n' '--workspace and --secret-root are required' >&2
  exit 2
fi

workspace_json=$("$INFRA_ROOT/scripts/workspace-registry.py" --registry "$REGISTRY" show --workspace "$WORKSPACE")
expected_root="${XDG_RUNTIME_DIR:?XDG_RUNTIME_DIR is required}/makersbrain/$WORKSPACE/current"
if [ "$SECRET_ROOT" != "$expected_root" ] || [ ! -L "$SECRET_ROOT" ]; then
  printf 'secret root must be the exporter-owned current link: %s\n' "$expected_root" >&2
  exit 1
fi
resolved_root=$(readlink -f -- "$SECRET_ROOT")
case "$resolved_root" in "$XDG_RUNTIME_DIR/makersbrain/$WORKSPACE/generations/"*) ;; *)
  printf 'secret generation escapes the workspace export root\n' >&2
  exit 1
;; esac
inventory="$resolved_root/inventory.json"
project_id=$(jq -r '.infisical_project_id' <<<"$workspace_json")
if ! jq -e --arg workspace "$WORKSPACE" --arg project "$project_id" '
  .schema == "makersbrain.workspace-secret-inventory.v1" and
  .workspace == $workspace and .infisical_project_id == $project
' "$inventory" >/dev/null; then
  printf 'workspace export inventory does not match the registry\n' >&2
  exit 1
fi

for required in \
  compose/control_api_database_url \
  compose/control_tenant_api_database_url \
  derived/rauthy_api_keys.json \
  derived/rauthy_enc_key_active \
  application/INVITATION_SIGNING_KEY_ID \
  application/INVITATION_VERIFICATION_PUBLIC_KEYS_JSON \
  recovery/BACKUP_AGE_IDENTITY \
  recovery/BACKUP_ENCRYPTION_KEY_ID; do
  [ -f "$resolved_root/$required" ] || { printf 'workspace export missing %s\n' "$required" >&2; exit 1; }
done

public_domain=$(jq -r '.public_domain' <<<"$workspace_json")
namespace=$(jq -r '.driver_workspace_namespace' <<<"$workspace_json")
workspace_config="$SCRIPT_DIR/workspaces/$WORKSPACE"
runtime_config="$workspace_config/runtime"
compose_secrets="$runtime_config/compose"
recovery_secrets="$runtime_config/recovery"
public_files="$runtime_config/public"
mkdir -p "$workspace_config/rauthy" "$compose_secrets" "$recovery_secrets" "$public_files"
chmod 0700 "$SCRIPT_DIR/workspaces" "$workspace_config" "$workspace_config/rauthy" "$runtime_config" "$compose_secrets" "$recovery_secrets" "$public_files"
for source in "$resolved_root"/compose/*; do
  [ -f "$source" ] || continue
  install -m 0444 "$source" "$compose_secrets/$(basename -- "$source")"
done
install -m 0444 "$resolved_root/recovery/BACKUP_AGE_IDENTITY" "$recovery_secrets/BACKUP_AGE_IDENTITY"
install -m 0444 "$resolved_root/application/INVITATION_VERIFICATION_PUBLIC_KEYS_JSON" "$public_files/invitation-verification-public-keys.json"
# These exact directories are bind-mounted into unprivileged containers. Their
# parent remains 0700, while files inside use Docker Compose secret semantics.
chmod 0555 "$recovery_secrets" "$public_files"
members_origin="https://control.$public_domain"
jq --arg members "$members_origin" '
  map(if .id == "mb-members" then
    .redirect_uris=[$members+"/oauth/callback"] |
    .post_logout_redirect_uris=[$members+"/signed-out"] |
    .allowed_origins=[$members] | .client_uri=$members
  else . end)
' "$SCRIPT_DIR/rauthy/clients.json" >"$workspace_config/rauthy/clients.json.tmp"
mv "$workspace_config/rauthy/clients.json.tmp" "$workspace_config/rauthy/clients.json"
chmod 0600 "$workspace_config/rauthy/clients.json"

temporary="$SCRIPT_DIR/.env.workspace.tmp"
cp "$SCRIPT_DIR/.env.example" "$temporary"
cat >>"$temporary" <<EOF
WORKSPACE=$WORKSPACE
COMPOSE_PROJECT_NAME=$namespace
WORKSPACE_DOCKER_NAMESPACE=$namespace
WORKSPACE_EXPORT_ROOT=$resolved_root
WORKSPACE_SECRET_ROOT=$compose_secrets
WORKSPACE_RECOVERY_SECRET_SOURCE=$recovery_secrets
WORKSPACE_INVITATION_PUBLIC_KEYS_FILE=$public_files/invitation-verification-public-keys.json
WORKSPACE_RAUTHY_API_KEYS_FILE=$resolved_root/derived/rauthy_api_keys.json
WORKSPACE_RAUTHY_CLIENTS_FILE=$workspace_config/rauthy/clients.json
PUBLIC_DOMAIN=$public_domain
CONTROL_DATA_MODE=synthetic
CONTROL_API_PORT=$(jq -r '.ports.control_api' <<<"$workspace_json")
CONTROL_WEB_PORT=$(jq -r '.ports.control_web' <<<"$workspace_json")
RAUTHY_HTTP_PORT=$(jq -r '.ports.rauthy_http' <<<"$workspace_json")
RAUTHY_HTTPS_PORT=$(jq -r '.ports.rauthy_https' <<<"$workspace_json")
ODOO_HTTP_PORT=$(jq -r '.ports.tenant_gateway' <<<"$workspace_json")
MINIO_API_PORT=$(jq -r '.ports.minio_api' <<<"$workspace_json")
MINIO_CONSOLE_PORT=$(jq -r '.ports.minio_console' <<<"$workspace_json")
BACKUP_S3_BUCKET=$(jq -r '.local_backup_bucket' <<<"$workspace_json")
BACKUP_S3_ENDPOINT=http://minio:9000
BACKUP_S3_REGION=us-east-1
BACKUP_ENCRYPTION_KEY_ID=$(cat "$resolved_root/recovery/BACKUP_ENCRYPTION_KEY_ID")
BACKUP_RETENTION_DAYS=7
CONTROL_BACKUP_SCHEDULER_ENABLED=true
RAUTHY_ENC_KEY_ACTIVE=$(cat "$resolved_root/derived/rauthy_enc_key_active")
INVITATION_SIGNING_KEY_ID=$(cat "$resolved_root/application/INVITATION_SIGNING_KEY_ID")
CONTROL_PRIVACY_LOOKUP_KEY_ID=$(cat "$resolved_root/application/CONTROL_PRIVACY_LOOKUP_KEY_ID")
CONTROL_PRIVACY_EXPORT_KEY_ID=$(cat "$resolved_root/application/CONTROL_PRIVACY_EXPORT_KEY_ID")
RAUTHY_BOOTSTRAP_ADMIN_EMAIL=owner+$WORKSPACE@example.test
CONTROL_OPERATOR_EMAILS=owner+$WORKSPACE@example.test
CONTROL_RELEASE_ID=workspace-$WORKSPACE-$(git -C "$CONTROL_ROOT" rev-parse --short=16 HEAD)
EOF
chmod 0600 "$temporary"
mv "$temporary" "$SCRIPT_DIR/.env"
printf 'configured %s from export generation %s\n' "$WORKSPACE" "$(jq -r '.generation' "$inventory")" >&2
