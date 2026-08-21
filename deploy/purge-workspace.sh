#!/usr/bin/env bash
# Delete one exact local synthetic workspace, including its local MinIO history.
set -euo pipefail

WORKSPACE=
CONFIRM=
while [ "$#" -gt 0 ]; do
  case "$1" in
  --workspace) WORKSPACE=${2:-}; shift 2 ;;
  --confirm-workspace) CONFIRM=${2:-}; shift 2 ;;
  *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done
case "$WORKSPACE" in dev1 | dev2 | dev3 | dev4) ;; *) printf 'invalid workspace\n' >&2; exit 2 ;; esac
if [ "$CONFIRM" != "$WORKSPACE" ]; then
  printf 'confirmation does not exactly match workspace\n' >&2
  exit 2
fi
namespace="mb-$WORKSPACE"
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
CONTROL_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
env_file="$SCRIPT_DIR/.env"
[ -f "$env_file" ] || { printf 'workspace environment is missing\n' >&2; exit 1; }
if ! grep -qx "WORKSPACE=$WORKSPACE" "$env_file" || ! grep -qx "WORKSPACE_DOCKER_NAMESPACE=$namespace" "$env_file"; then
  printf 'workspace environment does not match purge target\n' >&2
  exit 1
fi

printf 'purging Compose project %s and all of its local volumes\n' "$namespace" >&2
docker compose --project-name "$namespace" --env-file "$env_file" \
  -f "$SCRIPT_DIR/compose.yml" -f "$SCRIPT_DIR/compose.cloudflare.yml" \
  -f "$SCRIPT_DIR/compose.workspace.yml" down --volumes --remove-orphans

# Driver-created long-lived resources are outside Compose ownership. Match the
# exact workspace label; never a broad mb-* prefix.
while read -r container; do
  [ -n "$container" ] && docker rm -f "$container"
done < <(docker ps -aq --filter "label=mb.workspace=$namespace")
while read -r volume; do
  [ -n "$volume" ] && docker volume rm "$volume"
done < <(docker volume ls -q --filter "label=mb.workspace=$namespace")

export_root=${XDG_RUNTIME_DIR:?XDG_RUNTIME_DIR is required}/makersbrain/$WORKSPACE
if [ -e "$export_root" ]; then
  case "$export_root" in "$XDG_RUNTIME_DIR/makersbrain/$WORKSPACE") rm -rf -- "$export_root" ;; *) exit 1 ;; esac
fi
rm -rf -- "$SCRIPT_DIR/workspaces/$WORKSPACE"
rm -f -- "$env_file"
printf 'purged local synthetic workspace %s; Infisical and Cloudflare were not changed\n' "$WORKSPACE" >&2
