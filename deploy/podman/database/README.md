# Private PostgreSQL Podman bundle

This bundle runs only on the private database host as the rootless `mbdb`
account. The application bundle does not contain a PostgreSQL service.

Before activation, create the 16 password secrets named in
`postgres.container` plus `postgres_tls_certificate` and
`postgres_tls_private_key` in the `mbdb` Podman secret store. The release
installer must read them from the selected secret manager; neither the values
nor the TLS private key belong in the repository or release record.

The renderer accepts only the protected database data path, a private bind
address, an explicit application subnet and a digest-pinned mirrored image.
PostgreSQL requires TLS with SCRAM authentication and rejects every client
outside the application subnet. OCI network policy provides a second boundary.

```sh
python3 render.py --values values.json --output /tmp/makersbrain-db
python3 validate.py /tmp/makersbrain-db
```

Use the same signed release record and Cosign public key as the application
host. The database installer verifies the record and PostgreSQL image before
pulling, then atomically activates only `postgres.service`:

```sh
python3 release.py --values values.json --release-record release-record.json \
  --release-signature release-record.json.sig \
  --cosign-key /etc/makersbrain/release-cosign.pub --activate
```
