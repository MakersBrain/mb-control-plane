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
- `/var/lib/makersbrain/tenant-recovery-secrets` is a distinct mode `0700`
  restore-agent boundary. It contains only mode `0600` `age-identity.txt` and
  is mounted read-only. Backup creation receives the public recipient through
  an ephemeral job secret and never receives this recovery identity; restore
  jobs bind only the exact identity file, not either complete secret root.
- `postgres-ca.crt` is materialized as a regular, non-symlink file in that
  directory before activation. All staging and production PostgreSQL clients
  use `verify-full`; activation fails closed when the CA file is absent.
- `/etc/makersbrain/secrets/rauthy/config.toml` is mounted directly as Rauthy's
  scoped configuration secret. It supplies `pg_password` and Rauthy's supported
  `pg_tls_root_ca` PEM. The Quadlet fixes `PG_TLS=require` and
  `PG_TLS_NO_VERIFY=false`; activation proves that the embedded CA exactly
  matches the host CA file.
- The driver runs as container UID 0, which maps only to the unprivileged
  `tenant-runtime` host account under rootless Podman. It is not host root.
- `/etc/makersbrain` is an atomically switched symlink to an immutable
  configuration generation owned by the dedicated `tenant-runtime` account.
  `materialize.py` validates an explicit
  manifest and copies a tmpfs tree staged by Infisical Agent or the deployment
  helper without accepting secret values as arguments. Environment files are
  mode `0400`, secret files are `0600`, directories are `0700`, symlink sources
  and path traversal are rejected, and prior generations remain available for
  rollback. Secret values remain file references under `/run/secrets`; they are
  not written into Quadlets or release records.
- Images are pre-pulled and verified with the release Cosign public key before
  the units are installed. Every image value must contain an OCI digest.
- Third-party base images are mirrored into the controlled registry and signed
  there with the same release key; activation never trusts an upstream mutable
  tag or attempts to attach signatures to an upstream project.
- The rootless `podman.socket` is enabled for `tenant-runtime` and is never
  exposed over TCP.
- The digest-pinned `cloudflared` Quadlet uses only a file-scoped connector
  token from `/etc/makersbrain/secrets/cloudflared/tunnel-token`. Remote tunnel
  ingress targets `control-web:8080`, `control-api:8080`, `rauthy:8092` and
  `tenant-gateway:8080` on the private Podman network; the connector receives
  no database credentials or runtime socket.
- `control-mail-gateway` is the only process that receives the Scaleway TEM
  sending credential. It accepts the worker's bounded invitation payload over the
  private Podman network, requires an exact bearer credential, submits only to
  the fixed Paris TEM API and does not log recipient addresses or invitation
  capabilities. Staging additionally denies every recipient absent from its
  protected exact allowlist.
- `tenant-reconciliation` alone receives the distinct Cloudflare Custom
  Hostnames token and Scaleway domain/webhook credential. The former has no DNS
  authority; the latter has no general mail-sending authority. Both are file
  references in `/etc/makersbrain/control-worker-tenant-reconciliation.env` and
  are absent from the API, mail gateway, other workers and release records.
- Prometheus and Alertmanager have no published host port. Prometheus receives
  only the metrics-specific bearer mounted from
  `/etc/makersbrain/secrets/control-api/control_metrics_token`; it cannot call
  other internal APIs. Alertmanager reads the HTTPS receiver capability and
  its exact bearer from `/etc/makersbrain/secrets/alertmanager/webhook-url` and
  `webhook-token`. Both files are mode `0600` below a mode `0700` directory.
  The receiver must retain trigger, acknowledgement, recovery and resolution
  timestamps without storing tenant or provider payloads.

The two Prometheus jobs deliberately separate process liveness from the
database-backed metrics path. `MakersBrainApplicationUnavailable` fires when
the private live-metrics endpoint disappears;
`MakersBrainDatabaseUnavailable` fires only when that endpoint remains live
while the database-backed scrape fails. Backup freshness and restore-rehearsal
rules consume the normal control-plane metrics. Every rule is delivered to the
private Alertmanager, which uses `url_file` and `credentials_file` so receiver
capabilities never enter the signed bundle or release record.

The configuration is validator-tested with Prometheus `3.13.1` source digest
`sha256:3c42b892cf723fa54d2f262c37a0e1f80aa8c8ddb1da7b9b0df9455a35a7f893`
and Alertmanager `0.33.1` source digest
`sha256:9e082985f56f4c8c9f724e18f2288c6708f472e56a5286b8863d080434ea065d`.
Those upstream images are inputs, not runtime references: CI mirrors, scans,
SBOMs and signs them in the controlled registry, and the release values use
the resulting controlled-registry digests.

The mail gateway environment file contains only non-secret values and scoped
file references:

```dotenv
MAIL_GATEWAY_LISTEN=0.0.0.0:8080
MAIL_GATEWAY_SCW_ENDPOINT=https://api.scaleway.com/transactional-email/v1alpha1/regions/fr-par/emails
MAIL_GATEWAY_SCW_PROJECT_ID=00000000-0000-4000-8000-000000000000
MAIL_GATEWAY_SCW_DOMAIN_ID=00000000-0000-4000-8000-000000000000
MAIL_GATEWAY_FROM_EMAIL=notifications@notify.staging.makersbrain.net
MAIL_GATEWAY_FROM_NAME=MakersBrain
MAIL_GATEWAY_INTERNAL_TOKEN=@/run/secrets/mail_webhook_token
MAIL_GATEWAY_SCW_SECRET_KEY=@/run/secrets/scaleway_tem_secret_key
MAIL_GATEWAY_ALLOWED_RECIPIENTS_FILE=/run/secrets/mail_allowed_recipients
MAIL_GATEWAY_SNS_TOPIC_ARN=arn:scw:sns:fr-par:00000000-0000-4000-8000-000000000000:makersbrain-staging-tem
MAIL_GATEWAY_SNS_TRUST_CHAIN_FILE=/etc/makersbrain/scaleway-sns-fr-par-trust-chain.pem
MAIL_GATEWAY_EVENT_JOURNAL_FILE=/var/lib/makersbrain/mail-events/events.jsonl
MAIL_GATEWAY_CONTROL_EVENT_URL=http://control-api:8080/internal/v1/mail-events
MAIL_GATEWAY_CONTROL_EVENT_TOKEN=@/run/secrets/control_mail_event_token
```

Materialize the three credentials and recipient allowlist in
`/etc/makersbrain/secrets/control-mail-gateway` with directory mode `0700` and
file mode `0600`. The staging allowlist has one synthetic recipient address per
line; no wildcard or domain rule is accepted. The production file may be empty.
The email worker receives a separate mount of the submission bearer value,
never the TEM credential. The gateway's event bearer is independently scoped
to the control API delivery-event route.

The public Scaleway `fr-par` SNS trust chain is pinned in the release bundle and
mounted read-only by the Quadlet. Updating it therefore requires the same
reviewed, signed release process as application code; it is not an operator
download performed during activation.

`POST /v1/mail/events` is the only public gateway route. It requires the exact
SNS message-type and topic headers, the configured Topic ARN, signature version
1, a signing-certificate URL below Scaleway's fixed Paris SNS prefix and a
certificate chaining to the mounted long-lived Paris trust chain. Only then
does it confirm subscriptions or append privacy-safe delivery identifiers to
the bounded durable journal. Authenticated event records are then projected to
the control-plane delivery ledger; recipient addresses and provider response
text are never stored in the gateway journal.

Render a bundle with:

```sh
python3 render.py --values /secure/release/podman-values.json --output /tmp/makersbrain-quadlets
```

Stage the exact per-process environment and secret files from Infisical into a
root-only tmpfs directory, derive the explicit manifest from the rendered
candidate, validate it, then activate one locked generation. The manifest
contains paths and file classes only, never values:

```sh
python3 build_secret_stage.py \
  --source /run/makersbrain-infisical-export \
  --environment staging \
  --staging-root /run/makersbrain-staged \
  --references-output /run/makersbrain-secret-references.json \
  --postgres-host PRIVATE_DATABASE_HOST \
  --postgres-ca /var/lib/makersbrain/tenant-runtime-secrets/postgres-ca.crt \
  --driver-ca-path /var/lib/makersbrain/tenant-runtime-secrets/postgres-ca.crt \
  --release-cosign-key /etc/makersbrain/release-cosign.pub
python3 build_runtime_stage.py \
  --input /secure/release/makersbrain-runtime.json \
  --secret-input /run/makersbrain-secret-references.json \
  --rendered /secure/release/rendered-quadlets \
  --staging-root /run/makersbrain-staged
python3 build_materialization_manifest.py \
  --source /run/makersbrain-staged \
  --rendered /secure/release/rendered-quadlets \
  --generation RELEASE_ID \
  --output /secure/release/materialization-manifest.json
python3 materialize.py --source /run/makersbrain-staged \
  --manifest /secure/release/materialization-manifest.json \
  --rendered /secure/release/rendered-quadlets \
  --generation-root /etc/makersbrain-generations \
  --current-link /etc/makersbrain --uid TENANT_RUNTIME_UID \
  --gid TENANT_RUNTIME_GID --check
python3 materialize.py --source /run/makersbrain-staged \
  --manifest /secure/release/materialization-manifest.json \
  --rendered /secure/release/rendered-quadlets \
  --generation-root /etc/makersbrain-generations \
  --current-link /etc/makersbrain --uid TENANT_RUNTIME_UID \
  --gid TENANT_RUNTIME_GID
```

The runtime input is value-safe JSON with `shared` settings and exact
per-process overrides: credential-shaped settings must be scoped `@/run/...`
file references, not secret values. Per-process values keep database URLs and
other least-privilege identities distinct. The builder splits the document
into the exact process-owned files declared by `configuration-spec.json`,
requires every process setting, compares any Quadlet-hardcoded value for an
exact match, rejects unused settings, and refuses to overwrite a staged file.
Infisical supplies the referenced files separately into the same tmpfs staging
tree before the exact manifest is derived.

Resolve and review the dedicated account's numeric UID/GID before substituting
those documentation tokens; `materialize.py` accepts numeric IDs only. The
source directory must be removed after activation by the staging service.
Do not use a persistent working directory. Rollback is an atomic replacement of
the `current-link` with a symlink to a retained, reviewed generation; the tool
never deletes generations automatically.

The rendered bundle is mandatory. Every rendered environment file and secret
mount must be populated, and every manifest target must belong to one of those
runtime mounts. The later release preflight resolves every `@/run/...` reference
inside each process scope and supplies the exact-file completeness check for
directory mounts.

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

For an offline topology cutover, copy the verified release into the immutable
release store without changing the live Quadlet symlink or starting any unit,
enable and verify the database write fence, then atomically activate the
already-staged release only after restore/migration and read-only canaries pass:

```sh
python3 release.py --values /secure/release/podman-values.json \
  --release-record /secure/release/release-record.json \
  --release-signature /secure/release/release-record.json.sig \
  --cosign-key /etc/makersbrain/release-cosign.pub --stage-only
python3 database/write-fence.py enable
python3 database/write-fence.py verify
# Run migration and read-only canaries, then deliberately lower the fence once.
python3 database/write-fence.py disable
python3 release.py --values /secure/release/podman-values.json \
  --release-record /secure/release/release-record.json \
  --release-signature /secure/release/release-record.json.sig \
  --cosign-key /etc/makersbrain/release-cosign.pub --start-staged
```

The fence changes every runtime database role, terminates existing sessions so
they cannot retain a writable session default, and deliberately leaves only the
signed migration identity writable. After `disable`, recovery must preserve all
accepted writes; restoring the pre-cutover snapshot is no longer a valid rollback.

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

## Staging qualification

Each mandatory staging check writes one small JSON evidence file named after
the check in `qualification.py`. The file contains only the check name, passed
status, UTC start/completion times and a privacy-safe summary. Run:

Webshop promotion additionally requires independent Cloudflare DNS/TLS,
Scaleway mail, SumUp payment, Boxtal shipping, browser/accessibility and
observability-delivery checks;
the exact pass conditions are in
`../../docs/runbooks/webshop-paid-release-qualification.md`. A broad provider
or mail attestation cannot substitute for one of these named checks.

```sh
python3 qualification.py create \
  --release-record /secure/release/release-record.json \
  --evidence-dir /secure/staging-evidence/evidence \
  --output /secure/staging-evidence/staging-qualification.json
```

The `certify-staging` workflow independently rebuilds this record from the
immutable evidence artifact, signs it, and publishes it with all evidence
digests. `promote-production` accepts only that qualification artifact by OCI
digest, verifies its signature and evidence, and proves its release/image map
matches the staging release. A note, ticket number, mutable tag or arbitrary
approval string cannot unlock production promotion.

After authenticating `oras` to the controlled registry, the staging host
publishes the validated evidence set without putting a registry credential or
evidence content on the command line:

```sh
python3 publish_evidence.py \
  --release-record /secure/release/release-record.json \
  --evidence-dir /secure/staging-evidence/evidence \
  --repository registry.example/makersbrain/staging-evidence
```

Pass the printed digest reference to the `certify-staging` workflow.
