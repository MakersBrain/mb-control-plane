#!/bin/sh
set -eu
if [ ! -f deploy/.env ]; then
  echo "copy deploy/.env.example to deploy/.env first" >&2
  exit 1
fi
set -a
. deploy/.env
set +a
case "${PUBLIC_DOMAIN:-}" in
  dev[1-4].makersbrain.net) ;;
  *) echo "PUBLIC_DOMAIN must be dev1..dev4.makersbrain.net" >&2; exit 1 ;;
esac
if [ -z "${CLOUDFLARE_TUNNEL_TOKEN:-}" ]; then
  echo "CLOUDFLARE_TUNNEL_TOKEN is required" >&2
  exit 1
fi
umask 077
mkdir -p deploy/secrets
printf '%s' "$CLOUDFLARE_TUNNEL_TOKEN" > deploy/secrets/cloudflare-tunnel-token
echo "installed tunnel token for $PUBLIC_DOMAIN"
