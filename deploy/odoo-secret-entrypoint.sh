#!/bin/sh
set -eu

read_exact_secret() {
  name=$1
  path=$2
  [ ! -L "$path" ] && [ -f "$path" ] || {
    echo "$name secret file is unavailable" >&2
    exit 1
  }
  size=$(wc -c < "$path")
  [ "$size" -gt 0 ] && [ "$size" -le 65536 ] || {
    echo "$name secret file is empty or oversized" >&2
    exit 1
  }
  # The sentinel prevents command substitution from silently discarding every
  # trailing newline. Accept the conventional single terminal LF, but reject
  # embedded/extra lines and every carriage return.
  value=$(cat "$path"; printf x)
  value=${value%x}
  cr=$(printf '\r')
  case "$value" in
    *"$cr"*) echo "$name secret file contains a carriage return" >&2; exit 1;;
  esac
  case "$value" in
    *"
") value=${value%"
"};;
  esac
  case "$value" in
    *"
"*) echo "$name secret file must contain one line" >&2; exit 1;;
  esac
  [ -n "$value" ] || { echo "$name secret file is empty" >&2; exit 1; }
  printf '%s' "$value"
}

PASSWORD=$(read_exact_secret PASSWORD /run/secrets/odoo_postgres_password)
MB_CONTROL_BRIDGE_TOKEN=$(read_exact_secret MB_CONTROL_BRIDGE_TOKEN /run/secrets/odoo_bridge_token)
export PASSWORD MB_CONTROL_BRIDGE_TOKEN

exec /entrypoint.sh "$@"
