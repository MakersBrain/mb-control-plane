# Rootless Podman runtime bundle

This directory is the application-owned staging/production runtime contract.
Infrastructure installs the rendered files for the dedicated `tenant-runtime`
account in its rootless Quadlet search path. Docker Compose remains the local
development runtime.

All static and dynamic application containers use the same rootless Podman
account and `makersbrain.network`. This is required because rootless networks
are scoped to a Podman user. Only `control-container-driver.service` receives
the Podman Unix socket; the API, workers and tenant containers never receive it.

## Host contract

- Podman 5.x, cgroup v2 and user-systemd must be available.
- `tenant-runtime` has subordinate UID/GID ranges and lingering enabled.
- `/var/lib/makersbrain/tenant-runtime-secrets` is owned by `tenant-runtime`,
  mode `0700`, and backed up only through the encrypted recovery path.
- `postgres-ca.crt` is materialized as a regular, non-symlink file in that
  directory before activation. All staging and production PostgreSQL clients
  use `verify-full`; activation fails closed when the CA file is absent.
- `/etc/makersbrain/rauthy.env` supplies Rauthy's supported
  `PG_TLS_ROOT_CA` PEM value. The Quadlet fixes `PG_TLS=require` and
  `PG_TLS_NO_VERIFY=false`; activation rejects an absent CA value.
- The driver runs as container UID 0, which maps only to the unprivileged
  `tenant-runtime` host account under rootless Podman. It is not host root.
- `/etc/makersbrain/*.env` is rendered by the approved secret manager, mode
  `0400`, with one file per process. Secret values are file references under
  `/run/secrets`; they are not written into Quadlets.
- Images are pre-pulled and verified with the release Cosign public key before
  the units are installed. Every image value must contain an OCI digest.
- Third-party base images are mirrored into the controlled registry and signed
  there with the same release key; activation never trusts an upstream mutable
  tag or attempts to attach signatures to an upstream project.
- The rootless `podman.socket` is enabled for `tenant-runtime` and is never
  exposed over TCP.

Render a bundle with:

```sh
python3 render.py --values /secure/release/podman-values.json --output /tmp/makersbrain-quadlets
```

Validate before installation:

```sh
python3 validate.py /tmp/makersbrain-quadlets
systemd-analyze --user verify /tmp/makersbrain-quadlets/*.service
```

Verify a signed release without changing systemd, then activate it explicitly:

```sh
python3 release.py --values /secure/release/podman-values.json \
  --release-record /secure/release/release-record.json \
  --release-signature /secure/release/release-record.json.sig \
  --cosign-key /etc/makersbrain/release-cosign.pub
python3 release.py --values /secure/release/podman-values.json \
  --release-record /secure/release/release-record.json \
  --release-signature /secure/release/release-record.json.sig \
  --cosign-key /etc/makersbrain/release-cosign.pub --activate
```

Activation stores each rendered release separately and atomically changes the
single `makersbrain` Quadlet search-path symlink. A failed systemd activation
restores the prior symlink. Production records must include the successful
staging qualification reference for the exact same image map. The release
record itself is verified as a signed blob before any image is pulled or any
systemd state is changed.

The renderer refuses mutable image tags, development environments, unresolved
template values and production personal-data activation without an external
privacy activation record. Formal GDPR documentation can be completed later;
the technical activation hold remains fail-closed.
