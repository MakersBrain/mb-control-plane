#!/bin/sh
set -eu
if [ ! -f deploy/.env ]; then
  echo "run deploy/bootstrap-local-env.sh first" >&2
  exit 1
fi
if [ ! -d deploy/secrets/runtime ]; then
  echo "deploy/secrets/runtime is missing; run deploy/migrate-local-env-secrets.sh --apply for a legacy .env" >&2
  exit 1
fi
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 1; }
set -a
. deploy/.env
set +a
for name in CONTROL_RAUTHY_ADMIN_KEY CONTROL_RAUTHY_DEPLOYMENT_KEY
do
  eval "value=\${$name-}"
  case "$value" in
    @/run/secrets/*)
      leaf=${value#@/run/secrets/}
      case "$leaf" in ''|*/*|*..*) echo "unsafe secret reference for $name" >&2; exit 1;; esac
      secret_path="deploy/secrets/runtime/$leaf"
      [ -f "$secret_path" ] || { echo "missing secret reference for $name" >&2; exit 1; }
      value=$(cat "$secret_path")
      export "$name=$value"
      ;;
  esac
done
case "$CONTROL_RAUTHY_ADMIN_KEY" in makersbrain-runtime\$*) ;; *) echo "CONTROL_RAUTHY_ADMIN_KEY must be makersbrain-runtime\$<secret>" >&2; exit 1;; esac
rauthy_key_secret=${CONTROL_RAUTHY_ADMIN_KEY#*\$}
case "$rauthy_key_secret" in *[!A-Za-z0-9]*) echo "the Rauthy API-key secret must be alphanumeric" >&2; exit 1;; esac
if [ "${#rauthy_key_secret}" -lt 64 ]; then
  echo "the Rauthy API-key secret must be at least 64 characters" >&2
  exit 1
fi
case "$CONTROL_RAUTHY_DEPLOYMENT_KEY" in makersbrain-deployment\$*) ;; *) echo "CONTROL_RAUTHY_DEPLOYMENT_KEY must be makersbrain-deployment\$<secret>" >&2; exit 1;; esac
rauthy_deployment_secret=${CONTROL_RAUTHY_DEPLOYMENT_KEY#*\$}
case "$rauthy_deployment_secret" in *[!A-Za-z0-9]*) echo "the Rauthy deployment API-key secret must be alphanumeric" >&2; exit 1;; esac
if [ "${#rauthy_deployment_secret}" -lt 64 ]; then
  echo "the Rauthy deployment API-key secret must be at least 64 characters" >&2
  exit 1
fi

members_origin=http://localhost:${CONTROL_WEB_PORT:-4175}
if [ -n "${PUBLIC_DOMAIN:-}" ]; then
  case "$PUBLIC_DOMAIN" in dev[1-4].makersbrain.net) ;; *) echo "PUBLIC_DOMAIN must be dev1..dev4.makersbrain.net" >&2; exit 1;; esac
  members_origin="https://control.$PUBLIC_DOMAIN"
fi

mkdir -p deploy/secrets/rauthy
jq --arg members "$members_origin" '
  map(if .id == "makersbrain-members" then
    .redirect_uris=[$members+"/oauth/callback"] |
    .post_logout_redirect_uris=[$members+"/signed-out"] |
    .allowed_origins=[$members] | .client_uri=$members
  else . end)' deploy/rauthy/clients.json > deploy/secrets/rauthy/clients.json.tmp
mv deploy/secrets/rauthy/clients.json.tmp deploy/secrets/rauthy/clients.json
chmod 600 deploy/secrets/rauthy/clients.json
jq -n --arg secret "$rauthy_key_secret" --arg deployment_secret "$rauthy_deployment_secret" '[
  {"name":"makersbrain-runtime","secret":{"Plain":$secret},"access":[{"group":"Users","access_rights":["read","create","update"]},{"group":"Sessions","access_rights":["read","delete"]},{"group":"Events","access_rights":["read"]}]},
  {"name":"makersbrain-deployment","secret":{"Plain":$deployment_secret},"access":[{"group":"Clients","access_rights":["read","create","update","delete"]},{"group":"Secrets","access_rights":["read"]}]}
]' > deploy/secrets/rauthy/api_keys.json.tmp
mv deploy/secrets/rauthy/api_keys.json.tmp deploy/secrets/rauthy/api_keys.json
chmod 600 deploy/secrets/rauthy/api_keys.json
echo "generated Rauthy bootstrap manifests for $members_origin"
