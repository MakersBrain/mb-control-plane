# MakersBrain control plane

This directory is the self-contained control-plane package. It owns the Rust
API and queue workers, the artisan Members frontend, the control PostgreSQL
schema, Rauthy verification, Paperless/Azure/Odoo adapters, container builds,
and the machine-readable deployment contract. It does not import source code
or runtime files from sibling repositories.

## Verify

```sh
make check
make test
make build
make compose-config
```

Rust requires 1.96 and Node requires 22. Generated files and dependency trees
are ignored. `Cargo.lock` and `web/package-lock.json` are committed. The SQLx
migration ledger is explicitly fixed at `public._sqlx_migrations`; never make
it search-path-dependent because the database role and application schema are
both named `control`.

## Run the complete local topology

```sh
cp deploy/.env.example deploy/.env
# Replace every placeholder; never commit this file.
make configure
make up
```

Open the members UI at `http://localhost:4175` and Rauthy at
`http://rauthy.localhost:8092`. After creating a workshop with slug `atelier`,
the Docker driver publishes Odoo at `http://atelier.localhost:8169` and its
Paperless instance at `http://docs-atelier.localhost:8169`. The `.localhost`
name resolves to loopback in modern browsers. The mail fixture remains local;
tenant provisioning uses the authenticated Docker driver and the same private
HTTP contract used by later infrastructure drivers.

### HTTPS workspace through Cloudflare Tunnel

`../../makersbrain-infra/environments/development/developer-tunnels` owns the
remotely managed tunnel, DNS, exact service routes, and the development-only
workshop wildcard. After that state
has been applied, put its sensitive connector token and the allocated domain in
the ignored `deploy/.env`:

```dotenv
PUBLIC_DOMAIN=dev1.makersbrain.net
CLOUDFLARE_TUNNEL_TOKEN=<sensitive connector token>
```

Then run `make up-tunnel`. This regenerates the Rauthy clients with exact HTTPS
callbacks, starts Rauthy with its exact WebAuthn RP ID, and publishes:

- `control.dev1.makersbrain.net` — members UI
- `control-api.dev1.makersbrain.net` — Rust API
- `auth.dev1.makersbrain.net` — Rauthy
- `<workshop-slug>.dev1.makersbrain.net` — that workshop's database on the
  shared Odoo service (for example `atelier.dev1.makersbrain.net`; there is no
  `odoo-` prefix)
- `docs-<workshop-slug>.dev1.makersbrain.net` — that workshop's Paperless

The connector token is written to an ignored mode-0600 token file and passed to
`cloudflared` with `--token-file`, not as a command argument. This workspace is
strictly for synthetic test data. Stop it with `make down-tunnel`.

The hostname is a routing attribute, not an Odoo database name. Every workshop
uses an opaque physical identifier (`mb_<uuid>`). The gateway replaces any
client-supplied database header with the exact registered mapping and the
server-wide Odoo filter accepts only that opaque identifier. One Odoo process
and filestore volume are shared, while PostgreSQL databases remain isolated.
Odoo's native database list/manager is disabled.

Paperless is process-isolated per workshop: the driver creates one container,
one PostgreSQL role/database, and dedicated data, media, and consume volumes.
All Paperless containers share the Redis process, but each receives a distinct
ACL user, password, key prefix, and channel prefix. Redis uses AOF persistence
and `noeviction`; tenant containers cannot access another tenant's keys or
channels and cannot run Redis ACL, configuration, persistence, replication, or
other shared-service administration commands.

The owner-only **Workshop recovery** page exposes snapshots, portable backups,
restore, and non-routable duplicate requests. These are durable
`tenant.lifecycle` operations with typed slug confirmation, serialization,
audit events, retry status, and an automatic encrypted S3 safety backup. The
Docker driver operations are authenticated and persist their idempotency
outcomes. The driver owns tenant databases, volumes, Redis ACLs, Rauthy clients,
Paperless containers, and gateway routes. Lifecycle operations treat Odoo and,
when active, Paperless PostgreSQL plus the data/media/consume volumes as one
recovery unit. The shared Odoo process remains available to other workshops
while the selected workshop receives maintenance responses.

`control-backup-scheduler` queues one full workshop backup per 24-hour window
and performs a monthly isolated restore rehearsal of the newest verified S3
set. Rehearsals restore dumps only into disposable databases, persist their
result, and never cut over live workshop data.
Portable backups require the complete `BACKUP_S3_*`, `RESTORE_S3_*`, and
`BACKUP_AGE_*` configuration declared in `deploy/.env.example`; snapshots remain
available without S3. The dedicated helper image performs streaming zstd + age
encryption and AWS CLI multipart transfers. Application workers never receive
those credentials or the restore identity.

Rauthy is the only human credential authority. Odoo and Paperless use tenant
OIDC clients. The control API links a verified `(issuer, subject)` once and
reads workshop authority from PostgreSQL on every request. Local self-signup is
enabled only by the Compose harness; production should omit
`CONTROL_ALLOW_SELF_SIGNUP` and pre-provision or invite users.

The API publishes `/openapi.json`. Infrastructure consumes
`deploy/release-contract.json`; it injects secret values for the declared
environment names and selects the deployment driver for the target runtime.
Run `control-migrate` as a one-shot job before the API or workers; the supplied
Compose topology enforces that dependency on every clean start.

## Queues

Run exactly one queue per worker process:

```sh
control-worker membership-provisioning
control-worker invoice-capture
```

The full queue list is in the release contract. Operations use leases, fencing,
bounded exponential retry, dead letters, and an explicit unknown-outcome state.
Tenant credentials are referenced in PostgreSQL and resolved from the shared,
read-only `CONTROL_SECRET_ROOT` mount. The driver is the only process with
write access to that volume.

## Azure Document Intelligence

Paperless, invoice capture, and Azure extraction are enable-only workshop
modules. Enable them in that order from the control UI. New workshops provision
only Odoo and identity; existing workshops with a Paperless service are
backfilled as enabled by migration `0006_optional_document_services`.

Azure credentials are optional at process startup and are read only after a
workshop enables `azure-invoice-extraction`. Enabling that module fails safely
when `CONTROL_AZURE_ENDPOINT` or `CONTROL_AZURE_KEY` is absent. Infrastructure
may publish the key to
`makersbrain-runtime/dev/invoice-capture/AZURE_DOCUMENT_KEY` with
`../../makersbrain-infra/scripts/azure-document-key.sh`; the key is never read
from OpenTofu state by this package.

The invoice worker protects the trial subscription at three layers:

- structured UBL/Factur-X is parsed locally and consumes no Azure request;
- page reservations are transactional and idempotent per operation, with the
  monthly per-workshop ceiling set by `CONTROL_AZURE_MONTHLY_PAGE_LIMIT`;
- analyze submissions are paced across all worker replicas through PostgreSQL
  (`CONTROL_AZURE_ANALYZE_MIN_INTERVAL_MS`, 1100 ms by default).

Polling never runs faster than two seconds. Azure's successful-analyze and 429
`Retry-After` values take precedence; a throttled POST is returned to the queue
and its persisted `next_attempt_at` honors the provider delay (bounded to one
  hour) as well as exponential backoff. This prevents a restart or duplicate
  delivery from consuming the page allowance again.

With invoice capture enabled but Azure disabled, structured UBL, CII, and
Factur-X invoices continue to import locally. Unstructured documents remain in
Paperless for manual handling and do not consume an Azure request.

See [BACKUP-RESTORE.md](BACKUP-RESTORE.md) for paired recovery and
[`../CONTROL-PLANE-DESIGN.md`](../CONTROL-PLANE-DESIGN.md) for the architecture.
