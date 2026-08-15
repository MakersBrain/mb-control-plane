# Private PostgreSQL Podman bundle

This bundle runs only on the private database host as the rootless `mbdb`
account. The application bundle does not contain a PostgreSQL service.

Before activation, create the 16 password secrets named in
`postgres.container` plus `postgres_tls_certificate` and
`postgres_tls_private_key` in the `mbdb` Podman secret store. Also create
`pgbackrest_config`; it holds the encrypted, immutable object-storage recovery
repository configuration and its independently escrowed cipher passphrase. The release
installer must read them from the selected secret manager; neither the values
nor the TLS private key belong in the repository or release record.

The pgBackRest configuration must select the `makersbrain` stanza, the live
PostgreSQL path, TLS object-storage transport, AES-256-CBC repository
encryption, and retention consistent with the locked bucket. For example:

```ini
[makersbrain]
pg1-path=/var/lib/postgresql/data

[global]
repo1-type=s3
repo1-s3-endpoint=s3.fr-par.scw.cloud
repo1-s3-region=fr-par
repo1-s3-bucket=ENVIRONMENT_SPECIFIC_LOCKED_BUCKET
repo1-path=/postgresql
repo1-s3-key=SECRET_MANAGER_VALUE
repo1-s3-key-secret=SECRET_MANAGER_VALUE
repo1-cipher-type=aes-256-cbc
repo1-cipher-pass=INDEPENDENTLY_ESCROWED_SECRET_MANAGER_VALUE
repo1-retention-full=5
start-fast=y
process-max=2
```

The host continuously archives WAL, takes a randomized daily incremental
backup and a randomized weekly full backup. The object-storage bucket remains
the authoritative immutability and deletion boundary.

The renderer accepts only the protected database data path, a private bind
address, an explicit application subnet and a digest-pinned mirrored image.
PostgreSQL requires TLS with SCRAM authentication and rejects every client
outside the application subnet. OCI network policy provides a second boundary.

```sh
python3 render.py --values values.json --output /tmp/makersbrain-db
python3 validate.py /tmp/makersbrain-db
```

Use the same signed release record and Cosign public key as the application
host. The database installer verifies every secret, the record and PostgreSQL
image before pulling, then atomically activates PostgreSQL and its backup timers:

```sh
python3 release.py --values values.json --release-record release-record.json \
  --release-signature release-record.json.sig \
  --cosign-key /etc/makersbrain/release-cosign.pub --activate
```

Run a recovery drill into an empty, isolated directory. The tool never stops or
overwrites the live cluster and refuses targets outside the recovery-drill root:

```sh
python3 restore.py --values values.json \
  --target-directory /var/lib/makersbrain/postgresql/recovery-drills/quarterly-2026q3 \
  --target-time '2026-08-15 10:30:00+02'
```

Omit `--target-time` to restore the latest recoverable state. Record the exit
status, duration and restored target in staging qualification evidence; do not
place database rows, credentials, bucket keys or raw pgBackRest configuration
in evidence.
