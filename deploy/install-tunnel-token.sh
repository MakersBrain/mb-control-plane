#!/bin/sh
set -eu
source_file=
if [ "$#" -ne 0 ]; then
  if [ "$#" -ne 2 ] || [ "$1" != "--from-file" ]; then
    echo "usage: $0 [--from-file /secure/path/to/token]" >&2
    exit 2
  fi
  source_file=$2
  [ -f "$source_file" ] || { echo "$source_file is not a regular file" >&2; exit 1; }
fi
if [ ! -f deploy/.env ]; then
  echo "copy deploy/.env.example to deploy/.env first" >&2
  exit 1
fi
set -a
. deploy/.env
set +a
if [ -n "$source_file" ]; then
  CLOUDFLARE_TUNNEL_TOKEN=$(cat "$source_file")
fi
case "${PUBLIC_DOMAIN:-}" in
  dev[1-4].makersbrain.net) ;;
  *) echo "PUBLIC_DOMAIN must be dev1..dev4.makersbrain.net" >&2; exit 1 ;;
esac
if [ -z "${CLOUDFLARE_TUNNEL_TOKEN:-}" ]; then
  echo "CLOUDFLARE_TUNNEL_TOKEN is required" >&2
  exit 1
fi
umask 077
mkdir -p deploy/secrets/runtime
case "$CLOUDFLARE_TUNNEL_TOKEN" in
  @/run/secrets/cloudflare_tunnel_token)
    if [ ! -s deploy/secrets/runtime/cloudflare_tunnel_token ]; then
      echo "deploy/secrets/runtime/cloudflare_tunnel_token is empty" >&2
      exit 1
    fi
    ;;
  @*) echo "CLOUDFLARE_TUNNEL_TOKEN has an unsafe secret reference" >&2; exit 1 ;;
  *)
    if [ -e deploy/secrets/runtime/cloudflare_tunnel_token ]; then
      chmod 0600 deploy/secrets/runtime/cloudflare_tunnel_token
    fi
    printf '%s' "$CLOUDFLARE_TUNNEL_TOKEN" > deploy/secrets/runtime/cloudflare_tunnel_token
    chmod 0444 deploy/secrets/runtime/cloudflare_tunnel_token
    ;;
esac
echo "installed tunnel token for $PUBLIC_DOMAIN"
