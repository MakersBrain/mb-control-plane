#!/bin/sh
set -eu

# The gateway must never inherit live upstreams across a workspace boot. Build
# an empty selected generation before nginx is allowed to bind its listener.
# The temporary symlink and final selector live on the same volume, so `mv -T`
# is one atomic rename: nginx can see the old generation or the empty one, never
# a partially constructed selector. Other generation directories are retained
# for the future fenced publication reconciler and are never recursively swept.
mkdir -p /routes/generations/boot-live
# The staged publisher opens every selector component with O_NOFOLLOW and
# requires an owner-only write boundary. Normalize modes explicitly instead of
# depending on the container's umask.
chmod 0750 /routes /routes/generations /routes/generations/boot-live
find /routes/generations/boot-live -maxdepth 1 -type f \( -name '*.conf' -o -name '*.tmp' \) -delete
# One epoch-transition boot may still have flat release-recovery evidence. Move
# it into the selected generation without overwriting newer evidence, then
# remove obsolete flat live/staging files which Nginx no longer imports.
for legacy_backup in /routes/*.recovery.bak; do
  [ -e "$legacy_backup" ] || continue
  backup_name=${legacy_backup##*/}
  [ ! -e "/routes/generations/boot-live/$backup_name" ] || exit 1
  mv "$legacy_backup" "/routes/generations/boot-live/$backup_name"
done
find /routes -maxdepth 1 -type f \( -name '*.conf' -o -name '*.tmp' \) -delete
rm -f /routes/current.next
ln -s generations/boot-live /routes/current.next
mv -Tf /routes/current.next /routes/current
