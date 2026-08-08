#!/bin/sh
set -eu

target=${1:-deploy/.env}
if [ -e "$target" ]; then
  echo "$target already exists; refusing to overwrite local credentials" >&2
  exit 1
fi
if [ -z "${AZURE_DOCUMENT_KEY:-}" ]; then
  echo "AZURE_DOCUMENT_KEY must be injected by the secret manager" >&2
  exit 1
fi
command -v openssl >/dev/null 2>&1 || { echo "openssl is required" >&2; exit 1; }

random_hex() { openssl rand -hex 32; }
enc_active=$(date -u +%Y-%m-%d)
enc_key=$(openssl rand -base64 32 | tr -d '\n')
admin_password=$(random_hex)
paperless_password=$(random_hex)
temporary="${target}.tmp"
umask 077
{
  printf '%s\n' \
    "CONTROL_POSTGRES_PASSWORD=$(random_hex)" \
    "CONTROL_API_PORT=8180" \
    "CONTROL_WEB_PORT=4175" \
    "RAUTHY_HTTP_PORT=8093" \
    "ODOO_HTTP_PORT=8269" \
    "PAPERLESS_HTTP_PORT=8200" \
    "RAUTHY_HTTPS_PORT=18443" \
    "PUBLIC_DOMAIN=dev1.makersbrain.net" \
    "DEVELOPMENT_WORKSHOP_SLUG=atelier" \
    "RAUTHY_POSTGRES_PASSWORD=$(random_hex)" \
    "PAPERLESS_POSTGRES_PASSWORD=$(random_hex)" \
    "ODOO_POSTGRES_PASSWORD=$(random_hex)" \
    "RAUTHY_ENC_KEYS=$enc_active/$enc_key" \
    "RAUTHY_ENC_KEY_ACTIVE=$enc_active" \
    "RAUTHY_BOOTSTRAP_ADMIN_EMAIL=owner@example.test" \
    "RAUTHY_BOOTSTRAP_ADMIN_PASSWORD=$admin_password" \
    "RAUTHY_HQL_SECRET_RAFT=$(random_hex)" \
    "RAUTHY_HQL_SECRET_API=$(random_hex)" \
    "CONTROL_INTERNAL_TOKEN=$(random_hex)" \
    "ODOO_BRIDGE_TOKEN=$(random_hex)" \
    "PAPERLESS_SECRET_KEY=$(random_hex)" \
    "PAPERLESS_ADMIN_PASSWORD=$paperless_password" \
    "PAPERLESS_API_TOKEN=basic:local-admin:$paperless_password" \
    "PAPERLESS_OIDC_CLIENT_SECRET=$(random_hex)" \
    "CONTROL_RAUTHY_ADMIN_KEY='makersbrain-runtime\$$(random_hex)'" \
    "AZURE_DOCUMENT_ENDPOINT=https://makersbrain-development-documents.cognitiveservices.azure.com/" \
    "AZURE_DOCUMENT_KEY=$AZURE_DOCUMENT_KEY" \
    "MAIL_WEBHOOK_URL=http://integration-fixture:8080/send" \
    "MAIL_WEBHOOK_TOKEN=$(random_hex)" \
    "DEPLOYMENT_DRIVER_URL=http://integration-fixture:8080" \
    "DEPLOYMENT_DRIVER_TOKEN=$(random_hex)"
} > "$temporary"
chmod 0600 "$temporary"
mv "$temporary" "$target"
echo "generated $target for owner@example.test"
