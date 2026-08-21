#!/bin/sh
# Reconcile one local workspace bucket and its narrow writer/reader users.
set -eu
umask 077

read_secret() {
  value=$(cat "/run/secrets/$1")
  [ -n "$value" ] || { echo "empty MinIO secret: $1" >&2; exit 1; }
  printf '%s' "$value"
}

root_user=$(read_secret minio_root_user)
root_password=$(read_secret minio_root_password)
writer_access=$(read_secret backup_s3_access_key_id)
writer_secret=$(read_secret backup_s3_secret_access_key)
reader_access=$(read_secret restore_s3_access_key_id)
reader_secret=$(read_secret restore_s3_secret_access_key)
: "${BACKUP_S3_BUCKET:?BACKUP_S3_BUCKET is required}"

export MC_HOST_admin="http://${root_user}:${root_password}@minio:9000"
until mc ready admin >/dev/null 2>&1; do sleep 1; done
mc mb --ignore-existing --with-versioning "admin/$BACKUP_S3_BUCKET" >/dev/null
mc anonymous set none "admin/$BACKUP_S3_BUCKET" >/dev/null

policy_root=/tmp/mb-minio-policies
mkdir -p "$policy_root"
chmod 0700 "$policy_root"
cat >"$policy_root/writer.json" <<EOF
{"Version":"2012-10-17","Statement":[
  {"Effect":"Allow","Action":["s3:GetBucketLocation","s3:ListBucket","s3:ListBucketMultipartUploads"],"Resource":["arn:aws:s3:::$BACKUP_S3_BUCKET"]},
  {"Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:DeleteObject","s3:AbortMultipartUpload","s3:ListMultipartUploadParts"],"Resource":["arn:aws:s3:::$BACKUP_S3_BUCKET/*"]}
]}
EOF
cat >"$policy_root/reader.json" <<EOF
{"Version":"2012-10-17","Statement":[
  {"Effect":"Allow","Action":["s3:GetBucketLocation","s3:ListBucket"],"Resource":["arn:aws:s3:::$BACKUP_S3_BUCKET"]},
  {"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::$BACKUP_S3_BUCKET/*"]}
]}
EOF
chmod 0600 "$policy_root"/*.json

mc admin policy create admin mb-workspace-writer "$policy_root/writer.json" >/dev/null
mc admin policy create admin mb-workspace-reader "$policy_root/reader.json" >/dev/null
mc admin user add admin "$writer_access" "$writer_secret" >/dev/null 2>&1 || \
  mc admin user enable admin "$writer_access" >/dev/null
mc admin user add admin "$reader_access" "$reader_secret" >/dev/null 2>&1 || \
  mc admin user enable admin "$reader_access" >/dev/null
mc admin policy attach admin mb-workspace-writer --user "$writer_access" >/dev/null
mc admin policy attach admin mb-workspace-reader --user "$reader_access" >/dev/null

# Positive and negative probes use only the narrow identities. The denial checks
# fail startup if either user receives more authority than declared above.
probe=/tmp/mb-minio-probe
printf 'workspace-policy-probe' >"$probe"
export MC_HOST_writer="http://${writer_access}:${writer_secret}@minio:9000"
export MC_HOST_reader="http://${reader_access}:${reader_secret}@minio:9000"
mc cp "$probe" "writer/$BACKUP_S3_BUCKET/.policy-probe" >/dev/null
mc cat "reader/$BACKUP_S3_BUCKET/.policy-probe" >/dev/null
if mc cp "$probe" "reader/$BACKUP_S3_BUCKET/.reader-must-not-write" >/dev/null 2>&1; then
  echo 'restore reader unexpectedly uploaded an object' >&2
  exit 1
fi
if mc admin info writer >/dev/null 2>&1; then
  echo 'backup writer unexpectedly has administrative authority' >&2
  exit 1
fi
if mc rm "reader/$BACKUP_S3_BUCKET/.policy-probe" >/dev/null 2>&1; then
  echo 'restore reader unexpectedly deleted an object' >&2
  exit 1
fi
mc rm "writer/$BACKUP_S3_BUCKET/.policy-probe" >/dev/null
echo "local MinIO bucket and narrow policies ready: $BACKUP_S3_BUCKET"
