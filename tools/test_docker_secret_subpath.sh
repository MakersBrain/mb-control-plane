#!/bin/sh
set -eu

image='alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce'
volume="mb-secret-subpath-canary-$$"
cleanup() {
  docker volume rm "$volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

docker volume create "$volume" >/dev/null
docker run --rm --mount "type=volume,src=$volume,dst=/data" "$image" \
  sh -ec 'mkdir -p /data/tenant/a /data/tenant/b; printf tenant-a >/data/tenant/a/value; printf tenant-b >/data/tenant/b/value'
docker run --rm \
  --mount "type=volume,src=$volume,dst=/secrets,readonly,volume-subpath=tenant/a" \
  "$image" sh -ec '
    test "$(cat /secrets/value)" = tenant-a
    test ! -e /secrets/b/value
    if touch /secrets/must-fail 2>/dev/null; then exit 1; fi
  '

echo 'Docker secret subpaths are tenant-scoped and read-only'
