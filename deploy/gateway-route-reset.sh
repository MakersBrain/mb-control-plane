#!/bin/sh
set -eu

# The gateway must never inherit live upstreams across a driver restart. Saved
# recovery evidence is intentionally retained; only generated live/staging
# configuration is cleared before nginx is allowed to bind its listener.
find /routes -maxdepth 1 -type f \( -name '*.conf' -o -name '*.tmp' \) -delete
