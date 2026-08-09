#!/bin/sh
set -eu

network="mb-backup-smoke-$$"
server="mb-backup-smoke-server-$$"
workdir=$(mktemp -d)
cleanup() {
  docker rm -f "$server" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -rf -- "$workdir"
}
trap cleanup EXIT INT TERM

docker network create "$network" >/dev/null
docker run -d --rm --name "$server" --network "$network" \
  -e MINIO_ROOT_USER=smoke-access -e MINIO_ROOT_PASSWORD=smoke-secret-password \
  minio/minio:RELEASE.2025-04-22T22-12-26Z server /data >/dev/null

ready=false
for attempt in $(seq 1 30); do
  if docker run --rm --network "$network" minio/mc:RELEASE.2025-04-16T18-13-26Z \
    alias set smoke http://"$server":9000 smoke-access smoke-secret-password >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
test "$ready" = true
docker run --rm --network "$network" --entrypoint sh minio/mc:RELEASE.2025-04-16T18-13-26Z \
  -c "mc alias set smoke http://$server:9000 smoke-access smoke-secret-password >/dev/null && mc mb smoke/recovery >/dev/null"

docker run --rm --user 0:0 -v "$workdir:/work" makersbrain-control-backup:local sh -ec '
  umask 077
  age-keygen -o /work/identity >/dev/null 2>&1
  age-keygen -o /work/wrong-identity >/dev/null 2>&1
  recipient=$(age-keygen -y /work/identity)
  printf recovery-s3-smoke | zstd -q | age -r "$recipient" -o /work/object.enc
  sha256sum /work/object.enc | cut -d" " -f1 >/work/object.sha256
'
docker run --rm --user 0:0 --network "$network" -v "$workdir:/work" \
  -e AWS_ACCESS_KEY_ID=smoke-access -e AWS_SECRET_ACCESS_KEY=smoke-secret-password \
  -e AWS_DEFAULT_REGION=fr-par makersbrain-control-backup:local sh -ec \
  "aws --endpoint-url http://$server:9000 s3 cp --only-show-errors /work/object.enc s3://recovery/workshops/fixture/recovery/fixture/object.enc && aws --endpoint-url http://$server:9000 s3 cp --only-show-errors s3://recovery/workshops/fixture/recovery/fixture/object.enc /work/download.enc"
docker run --rm --user 0:0 -v "$workdir:/work" makersbrain-control-backup:local sh -ec '
  set -o pipefail
  test "$(sha256sum /work/download.enc | cut -d" " -f1)" = "$(cat /work/object.sha256)"
  test "$(age -d -i /work/identity /work/download.enc | zstd -q -d)" = recovery-s3-smoke
  if age -d -i /work/wrong-identity /work/download.enc >/dev/null 2>&1; then exit 1; fi
  printf tampered >>/work/download.enc
  test "$(sha256sum /work/download.enc | cut -d" " -f1)" != "$(cat /work/object.sha256)"
'

echo "encrypted S3 upload, download, wrong-key, and tamper checks passed"
