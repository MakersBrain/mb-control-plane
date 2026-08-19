#!/bin/sh
# Supply Cloudflare Access headers without placing either value in the signed
# Quadlet, Podman metadata, an environment file, or a shell history. The
# expanded values exist only in vmagent's process arguments inside its private
# container PID namespace; vmagent masks remoteWrite.headers in its own output.
set -eu
set +x

client_id=$(sed -e 's/\r$//' -e '$a\' /run/access/access-client-id)
client_secret=$(sed -e 's/\r$//' -e '$a\' /run/access/access-client-secret)

case "$client_id" in
  [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f].access) ;;
  *) echo "invalid Cloudflare Access client ID" >&2; exit 1 ;;
esac
[ "${#client_secret}" -ge 32 ] && [ "${#client_secret}" -le 512 ] || {
  echo "invalid Cloudflare Access client secret" >&2
  exit 1
}

exec /vmagent-prod \
  -remoteWrite.headers="CF-Access-Client-Id:${client_id}^^CF-Access-Client-Secret:${client_secret}" \
  "$@"
