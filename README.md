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

Open the members UI at `http://localhost:4175`, Rauthy at
`http://rauthy.localhost:8092`, Odoo at `http://atelier.localhost:8169`, and Paperless
at `http://localhost:8200`. The `.localhost` name resolves to loopback in
modern browsers. The local deployment/mail fixture implements the same narrow
HTTP boundary production infrastructure must supply; it never appears in the
release contract as a production process.

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
- `<workshop-slug>.dev1.makersbrain.net` — the single-tenant Odoo POC (for
  example `atelier.dev1.makersbrain.net`; there is no `odoo-` prefix)
- `paperless.dev1.makersbrain.net` — Paperless

The connector token is written to an ignored mode-0600 token file and passed to
`cloudflared` with `--token-file`, not as a command argument. This workspace is
strictly for synthetic test data. Stop it with `make down-tunnel`.

The hostname is a routing attribute, not an Odoo database name. New tenant
records use an opaque physical identifier (`mb_<uuid>`), and deployment must
map the registered hostname to the isolated tenant process. The existing local
POC keeps its historical `odoo` database so its data is not renamed in place;
it is still unrelated to the configured workshop hostname. Odoo's native
database list/manager is disabled.

The owner-only **Database & backups** page exposes snapshots, portable backups,
restore, and non-routable duplicate requests. These are durable
`tenant.lifecycle` operations with typed slug confirmation, serialization,
audit events, retry status, and an automatic pre-restore safety snapshot. The
included deployment fixture validates the contract and returns synthetic
artifacts; a production deployment driver must stop the tenant and create or
restore the real PostgreSQL database and filestore as one recovery unit.

Rauthy is the only human credential authority. Odoo and Paperless use tenant
OIDC clients. The control API links a verified `(issuer, subject)` once and
reads workshop authority from PostgreSQL on every request. Local self-signup is
enabled only by the Compose harness; production should omit
`CONTROL_ALLOW_SELF_SIGNUP` and pre-provision or invite users.

The API publishes `/openapi.json`. Infrastructure consumes
`deploy/release-contract.json`; it injects secret values for the declared
environment names and replaces the development deployment-driver fixture.
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
Tenant credentials are referenced in PostgreSQL but resolved only from
`CONTROL_SECRET__...` environment variables.

## Azure Document Intelligence

Development uses the S0 resource at
`https://makersbrain-development-documents.cognitiveservices.azure.com/`.
Infrastructure publishes its live key to
`makersbrain-runtime/dev/invoice-capture/AZURE_DOCUMENT_KEY` with
`../../makersbrain-infra/scripts/azure-document-key.sh`; the key is never read
from OpenTofu state by this package. Deployment maps that secret and the public
endpoint to `CONTROL_AZURE_KEY` and `CONTROL_AZURE_ENDPOINT`.

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

See [BACKUP-RESTORE.md](BACKUP-RESTORE.md) for paired recovery and
[`../CONTROL-PLANE-DESIGN.md`](../CONTROL-PLANE-DESIGN.md) for the architecture.
