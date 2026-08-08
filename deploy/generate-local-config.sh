#!/bin/sh
set -eu
if [ ! -f deploy/.env ]; then
  echo "copy deploy/.env.example to deploy/.env and replace every placeholder" >&2
  exit 1
fi
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 1; }
set -a
. deploy/.env
set +a
case "$PAPERLESS_OIDC_CLIENT_SECRET" in replace-*|'') echo "set PAPERLESS_OIDC_CLIENT_SECRET first" >&2; exit 1;; esac
case "$PAPERLESS_OIDC_CLIENT_SECRET" in *[!A-Za-z0-9]*) echo "PAPERLESS_OIDC_CLIENT_SECRET must be alphanumeric" >&2; exit 1;; esac
if [ "${#PAPERLESS_OIDC_CLIENT_SECRET}" -lt 64 ]; then
  echo "PAPERLESS_OIDC_CLIENT_SECRET must be at least 64 characters" >&2
  exit 1
fi
case "$CONTROL_RAUTHY_ADMIN_KEY" in makersbrain-runtime\$*) ;; *) echo "CONTROL_RAUTHY_ADMIN_KEY must be makersbrain-runtime\$<secret>" >&2; exit 1;; esac
rauthy_key_secret=${CONTROL_RAUTHY_ADMIN_KEY#*\$}
case "$rauthy_key_secret" in *[!A-Za-z0-9]*) echo "the Rauthy API-key secret must be alphanumeric" >&2; exit 1;; esac
if [ "${#rauthy_key_secret}" -lt 64 ]; then
  echo "the Rauthy API-key secret must be at least 64 characters" >&2
  exit 1
fi

members_origin=http://localhost:${CONTROL_WEB_PORT:-4175}
development_workshop_slug=${DEVELOPMENT_WORKSHOP_SLUG:-atelier}
case "$development_workshop_slug" in
  [a-z0-9]*[a-z0-9]) ;;
  *) echo "DEVELOPMENT_WORKSHOP_SLUG must be a lower-case DNS label" >&2; exit 1;;
esac
case "$development_workshop_slug" in *[!a-z0-9-]*) echo "DEVELOPMENT_WORKSHOP_SLUG must be a lower-case DNS label" >&2; exit 1;; esac
odoo_origin=http://${development_workshop_slug}.localhost:${ODOO_HTTP_PORT:-8169}
paperless_origin=http://localhost:${PAPERLESS_HTTP_PORT:-8200}
if [ -n "${PUBLIC_DOMAIN:-}" ]; then
  case "$PUBLIC_DOMAIN" in dev[1-4].makersbrain.net) ;; *) echo "PUBLIC_DOMAIN must be dev1..dev4.makersbrain.net" >&2; exit 1;; esac
  members_origin="https://control.$PUBLIC_DOMAIN"
  odoo_origin="https://$development_workshop_slug.$PUBLIC_DOMAIN"
  paperless_origin="https://paperless.$PUBLIC_DOMAIN"
fi

mkdir -p deploy/secrets/rauthy
jq --arg members "$members_origin" --arg odoo "$odoo_origin" '
  map(if .id == "makersbrain-members" then
    .redirect_uris=[$members+"/oauth/callback"] |
    .post_logout_redirect_uris=[$members+"/signed-out"] |
    .allowed_origins=[$members] | .client_uri=$members
  elif .id == "makersbrain-odoo-local" then
    .redirect_uris=[$odoo+"/auth_oauth/signin"] |
    .post_logout_redirect_uris=[$odoo+"/web/login"] |
    .allowed_origins=[$odoo] | .client_uri=$odoo
  else . end)' deploy/rauthy/clients.json |
jq --arg secret "$PAPERLESS_OIDC_CLIENT_SECRET" --arg paperless "$paperless_origin" '. + [{
  id:"makersbrain-paperless-local",name:"Local Paperless",secret:{Plain:$secret},
  redirect_uris:[$paperless+"/accounts/oidc/rauthy/login/callback/"],
  post_logout_redirect_uris:[$paperless+"/"],
  allowed_origins:[$paperless],enabled:true,
  flows_enabled:["authorization_code"],access_token_alg:"EdDSA",id_token_alg:"EdDSA",
  auth_code_lifetime:60,access_token_lifetime:300,
  scopes:["openid","profile","email"],default_scopes:["openid","profile","email"],
  challenges:["S256"],force_mfa:false,client_uri:$paperless
}]' > deploy/secrets/rauthy/clients.json.tmp
mv deploy/secrets/rauthy/clients.json.tmp deploy/secrets/rauthy/clients.json
chmod 600 deploy/secrets/rauthy/clients.json
jq -n --arg secret "$rauthy_key_secret" '[{"name":"makersbrain-runtime","secret":{"Plain":$secret},"access":[{"group":"Users","access_rights":["read","create","update"]},{"group":"Sessions","access_rights":["read","delete"]},{"group":"Events","access_rights":["read"]}]}]' > deploy/secrets/rauthy/api_keys.json.tmp
mv deploy/secrets/rauthy/api_keys.json.tmp deploy/secrets/rauthy/api_keys.json
chmod 600 deploy/secrets/rauthy/api_keys.json
echo "generated Rauthy bootstrap manifests for $members_origin"
