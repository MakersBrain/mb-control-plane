#!/bin/sh
set -eu

# Compatibility adapter for upstream images that do not support Docker's
# conventional *_FILE settings. Values are resolved only from the fixed secret
# mount, are never printed, and are exported after the container has started so
# they do not enter the rendered Compose model or Docker image metadata.
for name in \
  PG_PASSWORD BOOTSTRAP_ADMIN_PASSWORD_PLAIN ENC_KEYS HQL_SECRET_RAFT \
  HQL_SECRET_API PASSWORD MB_CONTROL_BRIDGE_TOKEN
do
  eval "value=\${$name-}"
  case "$value" in
    @/run/secrets/*)
      path=${value#@}
      leaf=${path#/run/secrets/}
      case "$leaf" in
        ''|*/*|*..*) echo "unsafe secret reference for $name" >&2; exit 1 ;;
      esac
      [ -f "$path" ] || { echo "missing secret reference for $name" >&2; exit 1; }
      value=$(cat "$path")
      case "$value" in
        *"
"*) echo "multiline secret rejected for $name" >&2; exit 1 ;;
      esac
      export "$name=$value"
      ;;
  esac
done

exec "$@"
