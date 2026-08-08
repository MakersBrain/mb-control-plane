# MakersBrain control-plane implementation plan

Status: proposed implementation baseline
Application source: `../makersbrain`
Tenant Odoo integration: this repository
Deployment target: `../makersbrain-infra`

## 1. Outcome and boundaries

The control plane manages the MakersBrain service, not an artisan's business
records. It owns people, workshop memberships, invitations, subscriptions,
domains, tenant lifecycle, provisioning state and operational audit. Odoo owns
sales, stock, accounting and workshop data. Paperless-ngx owns captured source
documents. Rauthy owns human credentials and authentication.

The implementation uses Rust for both the HTTP API and every asynchronous
worker. Browser applications never receive Rauthy administration credentials,
Paperless service tokens, Odoo integration credentials or Azure keys.

The first release keeps these hard boundaries:

- one central control-plane PostgreSQL database;
- one Rauthy deployment per environment;
- one shared Odoo runtime pool for the first deployment, with no database
  selector or manager exposed;
- one Odoo database and filestore per workshop;
- one isolated Paperless application, database and document-volume set per
  workshop;
- one shared Redis service initially, with an opaque Paperless key/channel
  prefix and Redis ACL identity per workshop;
- one shared Azure Document Intelligence resource per environment, with usage
  attributed and limited per workshop;
- no supplier invoice, attachment or extracted line stored in the control-plane
  database;
- no Paperless or Azure credential stored in Odoo;
- no Rauthy password, passkey or recovery secret stored outside Rauthy.

## 2. Reuse rather than rewrite

`../makersbrain` remains the source repository for the control-plane binaries.
The existing `apps/admin-api` is the starting point, not reference code to be
reimplemented. Reuse its existing behavior and tests where the platform
semantics still match.

| Existing component | Decision |
| --- | --- |
| Axum router, middleware and generated OpenAPI | Reuse directly |
| Rauthy JWT/JWKS validation and stable `(issuer, subject)` identity link | Reuse directly |
| Workshops, users, memberships, invitations and last-owner database guard | Reuse and extend public workshop roles |
| Durable commands, operation leases, retry state and worker heartbeats | Reuse as the provisioning foundation |
| Rauthy adapter and identity-operation worker | Reuse; add tenant application-role reconciliation |
| Transactional mail outbox and delivery worker | Reuse for invitations and lifecycle notices |
| Audit, diagnostics, dead-letter and release-evidence surfaces | Reuse directly |
| Admin console authentication and API client | Reuse; split operator and artisan navigation by permission |
| Old `core-api`, `core-worker` business domains | Do not carry forward; Odoo now owns those records |
| Old shared-PostgreSQL tenant runtime provisioning | Replace with Odoo database plus Paperless deployment provisioning |

Before extraction, record the source commit and preserve its contract tests.
Move code only when a clean crate boundary is required; do not fork identical
copies between repositories. Likely reusable crates are `email`, `outbox`,
`persistence`, `policy`, `contract`, `kernel` identifiers/errors and the
admin-api identity modules.

## 3. Target topology

```text
Browser
  -> portal / members frontend
       -> Rust control API -> control PostgreSQL
                           -> durable operations/outbox

Rust workers
  -> Rauthy Admin API
  -> shared Odoo internal API, selecting an exact tenant database
  -> tenant Paperless API
  -> deployment/provisioning driver
  -> mail provider
  -> Azure Document Intelligence

Rauthy
  -> OIDC client: portal
  -> OIDC client: each tenant Odoo
  -> OIDC client: each tenant Paperless

Shared application services
  -> Odoo runtime pool
  -> PostgreSQL cluster
  -> Redis broker
  -> exact-host tenant gateway

Per workshop
  -> Odoo database + filestore
  -> Paperless application + database + data/media/consume volumes
  -> Redis ACL identity + opaque key/channel prefix
  -> invoice-capture queue state
```

Public production names should remain one label beneath `makersbrain.app` so
the current edge certificate model in `makersbrain-infra` remains valid:

| Surface | Production example |
| --- | --- |
| Portal and Members UI | `app.makersbrain.app` |
| Control API | `api.makersbrain.app` |
| Rauthy login/account UI | `auth.makersbrain.app` |
| Operator console | `console.makersbrain.app` |
| Tenant Odoo | `<workshop>.makersbrain.app` |
| Tenant Paperless | `docs-<workshop>.makersbrain.app` |

Workshop slugs are immutable in the first release. Hostname, opaque Odoo
database identifier and runtime location are separate records from the start.
The gateway resolves an exact registered hostname to an anchored database
filter; neither the slug nor hostname is used as a physical database name.

The first deployment backend is a private Docker deployment driver. It creates
databases, filestore namespaces, Paperless containers and volumes, Redis ACLs,
OIDC clients and gateway routes through the same idempotent HTTP contract used
by the provisioning worker. It has a persistent operation ledger and accepts
only pinned images and generated resource names; callers cannot submit Docker
commands, images, bind mounts or Compose YAML. It is never publicly routed.
`makersbrain-infra` later replaces this backend with its Podman/systemd driver
without changing control-plane operations or application adapters.

## 4. Rust workspace and processes

Keep one Rust workspace in `../makersbrain` with small composition roots:

```text
apps/
  admin-api/                 control-plane HTTP API
  admin-worker/              one queue selected per process
  admin-console/             operator and workshop Members frontend
crates/
  control-domain/            tenant, membership, invite and lifecycle rules
  control-persistence/       SQLx queries and transaction boundaries
  control-contract/          API types and OpenAPI policy metadata
  control-provisioning/      idempotent provisioning steps
  adapter-rauthy/            Rauthy administration client
  adapter-odoo/              tenant Odoo JSON-2/internal client
  adapter-paperless/         Paperless API and health client
  adapter-azure-invoice/     Azure prebuilt-invoice client
  invoice-capture/           structured detection and normalization
  email/ outbox/ policy/     retained shared crates
```

The API validates, authorizes and records commands. It does not call Rauthy,
Odoo, Paperless, Azure or infrastructure providers inline. Every external
mutation is a durable operation executed by a worker.

Run one queue per worker process, using the existing lease/retry/heartbeat
pattern:

| Queue | Responsibility |
| --- | --- |
| `identity-operations` | Rauthy users, client roles and session revocation |
| `tenant-provisioning` | Odoo/Paperless deployment and tenant initialization |
| `membership-provisioning` | Reconcile one membership into Rauthy, Odoo and Paperless |
| `invoice-capture` | Fetch, classify, extract and submit one document revision |
| `email-delivery` | Invitation and lifecycle messages |
| `tenant-reconciliation` | Detect and repair cross-system drift |
| `tenant-lifecycle` | backup, export, suspend, restore and retained deletion |

Each queue has a distinct database role and receives only the provider secrets
it needs. Deploying the same worker image with different subcommands is fine;
running all queues in one process is not.

## 5. Authoritative control-plane data

Extend the existing control schema rather than introduce a second platform
database. All identifiers are opaque UUIDs; user-facing slugs are not primary
keys.

Core records:

- `users`: internal person record, status, locale and global authority epoch;
- `external_identities`: unique verified Rauthy `(issuer, subject)` link;
- `workshops`: immutable slug, display/legal identity, plan and lifecycle;
- `memberships`: workshop, user, public role, status and membership epoch;
- `invitations`: normalized email, requested role, hashed token, expiry and
  lifecycle timestamps;
- `service_instances`: tenant Odoo/Paperless logical instance identifiers,
  release, location and health, never credentials;
- `runtime_clusters`: shared Odoo/PostgreSQL/Redis placement and release
  identity, allowing workshops to move to another shard later;
- `oidc_clients`: Rauthy client identifier, redirect metadata and provisioning
  status, never the client secret;
- `operations` and `operation_steps`: stable idempotency key, desired epoch,
  attempts, lease, next retry, terminal result and safe error classification;
- `subscriptions` and `entitlements`: plan state, effective limits, expiry and
  signed-entitlement version;
- `domains`: hostname, verification state and routing target;
- `usage_counters`: Azure pages and other billable units per workshop/month;
- `audit_events`: actor, authority, command, target, correlation id and result.

Add `desired_epoch` and `applied_epoch` per external target. A worker may mark a
membership fully reconciled only when Rauthy, Odoo and Paperless all report the
current desired epoch. Partial success remains visible and retryable.

The supported public workshop roles are:

| Public role | Odoo mapping | Paperless mapping | Control-plane authority |
| --- | --- | --- | --- |
| `viewer` | read-only workshop access | view documents | none |
| `artisan` | ordinary sales, stock and workshop work | upload/view own workshop documents | none |
| `accountant` | accounting and invoice review | view/edit invoice documents and metadata | none |
| `studio_manager` | operational manager groups | manage tenant documents and correspondents | invite/change non-owner members when delegated |
| `owner` | studio manager application rights | same document rights as studio manager | billing, ownership and full membership authority |

Raw Odoo groups, Paperless groups and Rauthy roles are implementation details.
The frontend and public API expose only the roles above. `owner` is never an
invitation option; ownership changes through a separate two-party operation
with a database-enforced last-owner guard.

## 6. Authentication and authorization

Rauthy is the only human credential authority. Use Authorization Code with
PKCE for browser clients. Validate issuer, audience, signature, expiry and
nonce/state as appropriate. Authorization joins only on verified
`(issuer, subject)`, never on a mutable email address.

Create independent Rauthy clients for:

- the MakersBrain portal;
- the operator console;
- each tenant's Odoo redirect URI;
- each tenant's Paperless redirect URI.

Odoo uses OCA `auth_oidc` and binds the Rauthy subject to the provisioned
`res.users`. Paperless uses its supported OIDC/social-account path. Ordinary
human passwords are disabled in both after a tested operator recovery process
exists. Break-glass Odoo and Paperless accounts are sealed operator identities,
not workshop owners.

Authentication does not grant workshop access by itself. On every control API
request, resolve the active internal user and membership, verify its epoch and
evaluate a named permission. Permission reductions take effect on the next
request, independent of access-token lifetime.

Rauthy Admin remains operator-only. The control-plane worker holds a narrowly
scoped server credential. Artisan owners never edit Rauthy clients, groups or
roles directly.

## 7. Members frontend and invitation flow

The MakersBrain frontend provides two clearly separated surfaces:

- Rauthy's branded account pages for sign-in, email verification, password,
  passkey, MFA and recovery management;
- `/workshops/:id/members` for tenant membership and invitation management.

The Members page shows member name/email, public role, access state, last
successful reconciliation, outstanding target errors and safe retry actions.
It supports invite, resend, revoke, role change, removal and ownership
transfer. It never displays raw downstream group names or secrets.

Invitation sequence:

1. Authorized owner or delegated studio manager submits normalized email,
   public role and locale with an idempotency key.
2. The API stores only a SHA-256 digest of a random, single-use token and
   queues the invitation email in the same database transaction.
3. The recipient opens the link, authenticates or registers in Rauthy and
   verifies the invited email.
4. The API revalidates invitation state, verified email and inviter authority,
   atomically consumes the invitation and creates the membership.
5. It increments the membership epoch and records a
   `membership-provisioning` operation.
6. Workers reconcile the Rauthy tenant role, Odoo user/groups and Paperless
   account/groups.
7. The frontend shows partial progress until all targets have applied the same
   epoch, then offers Odoo and Documents links.

Resending revokes the previous token. Acceptance, delivery and provisioning
are idempotent. Removing a member immediately revokes the control-plane
membership, bumps its epoch, then durably removes the tenant Rauthy authority,
archives/disables the Odoo user, disables Paperless access and revokes known
sessions. Historical accounting and document audit records are retained.

## 8. Tenant provisioning workflow

Creating a workshop records the workshop, first owner and a stable operation
key such as `provision:<workshop-id>:<generation>` in one transaction. The
worker advances explicit, repeatable steps:

1. reserve and validate the immutable slug and hostnames;
2. create the Rauthy Odoo and Paperless clients and store their non-secret ids;
3. ask the deployment driver to allocate an opaque Odoo database and filestore
   namespace on the selected shared runtime, an isolated Paperless application,
   database and volumes, and an ACL-restricted prefix on shared Redis;
4. initialize the Odoo database without demo data and install pinned modules;
5. create company defaults and provision the owner by Rauthy subject, without
   a local human password;
6. initialize Paperless, pre-create allowlisted groups and configure OIDC;
7. provision the owner membership to all three targets;
8. publish routing only after Odoo, Paperless and OIDC health checks pass;
9. issue signed entitlements and send activation/onboarding mail;
10. record release identifiers and retained verification evidence.

A retry first observes the target, then creates or updates only what is
missing. Provider timeouts are classified as unknown outcomes and reconciled
before another create is attempted. No step compensates by deleting a working
database or document archive.

## 9. Paperless and invoice capture

Paperless is an archive and intake system, not an accounting engine. Each
workshop receives an isolated Paperless application boundary with its own
database, secret key, OIDC client and data/media/consume backup set. Paperless
instances share Redis initially, using `PAPERLESS_REDIS_PREFIX` for all keys and
channels plus a unique Redis ACL identity restricted to that opaque prefix.
Redis database numbers are not the tenant boundary. Documents may arrive by
browser upload, scanner, phone photo, consume directory or inbound email.

Paperless emits a workflow event containing tenant and document identity. The
Rust `invoice-capture` worker then:

1. validates the signed/internal event and derives the workshop from the
   endpoint credential, never from an untrusted body field;
2. retrieves document metadata and the immutable original from Paperless;
3. computes a content digest and records the document revision idempotency key;
4. detects Factur-X/CII or UBL and parses structured content locally;
5. otherwise submits the PDF/image to Azure Document Intelligence
   `prebuilt-invoice`, polling under a bounded timeout;
6. normalizes supplier, identifiers, dates, currency, lines, taxes, totals,
   confidence, provider model/version and page count into a provider-neutral
   contract;
7. validates arithmetic and confidence policy without inventing missing data;
8. calls the tenant `mb_invoice_capture` internal endpoint;
9. Odoo matches an existing supplier and creates or updates one draft supplier
   bill, attaches the source, and records external identity/audit metadata;
10. records completion and Azure usage, then applies a Paperless tag/status.

Odoo never posts or pays the bill automatically and never silently creates a
supplier, product, account or tax from OCR output. Ambiguous supplier matches,
low-confidence required fields and non-reconciling totals remain reviewable.
User corrections win over later retries; a changed content digest creates a
new source revision rather than overwriting reviewed values.

Azure endpoint and key exist only in the invoice worker's secret environment.
Logs contain correlation ids, document ids, page counts, timings and error
classes—not invoice text, images, access tokens or provider payloads. Factur-X
and UBL fixtures must prove zero Azure calls.

## 10. API surface

Keep `/v1` and generated OpenAPI from the Rust router. Mutating requests use an
`Idempotency-Key`; updates that can lose changes use `If-Match`/ETag. Return a
stable operation resource for asynchronous work.

Minimum artisan-facing routes:

```text
GET    /v1/me
GET    /v1/workshops
POST   /v1/workshops
GET    /v1/workshops/{id}
GET    /v1/workshops/{id}/members
POST   /v1/workshops/{id}/invitations
POST   /v1/invitations/{id}/resend
DELETE /v1/invitations/{id}
GET    /v1/invitations/{token}/validate
POST   /v1/invitations/{token}/accept
PATCH  /v1/workshops/{id}/members/{user_id}
DELETE /v1/workshops/{id}/members/{user_id}
POST   /v1/workshops/{id}/ownership-transfers
GET    /v1/workshops/{id}/integrations
GET    /v1/workshops/{id}/database
POST   /v1/workshops/{id}/database/snapshots
POST   /v1/workshops/{id}/database/backups
POST   /v1/workshops/{id}/database/restores
POST   /v1/workshops/{id}/database/duplicates
GET    /v1/operations/{id}
POST   /v1/operations/{id}/retry
```

Internal routes use separate audiences and service identities:

```text
POST /internal/v1/paperless/{workshop_id}/events
POST /internal/v1/tenants/{workshop_id}/reconcile
POST /internal/v1/entitlements/{workshop_id}/ack
```

The tenant Odoo receiver is implemented in this repository and accepts only
the narrow commands required for user/group reconciliation, entitlement
application and normalized invoice capture. It does not expose general Odoo
administration through the control plane.

## 11. Secrets and service identities

Infisical remains the deployment source of truth. `makersbrain-infra` grants
each process only its environment and queue-specific secret path.

| Process | Secrets allowed |
| --- | --- |
| Control API | control DB API role, Rauthy verification/JWKS configuration |
| Identity worker | control DB worker role, least-privilege Rauthy API key |
| Provisioning worker | deployment driver credential and secret-reference write capability |
| Membership worker | per-tenant Odoo/Paperless service credential references |
| Invoice worker | Paperless read token, tenant Odoo capture token, Azure endpoint/key |
| Email worker | mail provider credential only |
| Reconciliation worker | read/reconcile credentials, no billing or deletion authority |

Secrets are referenced by opaque secret ids in operation payloads; their
values never enter PostgreSQL, job JSON, audit rows, OpenAPI responses or logs.
Rotate Rauthy and tenant integration credentials independently. A tenant
backup contains its application data, not control-plane or Azure credentials.

## 12. Deployment contract with `makersbrain-infra`

`../makersbrain-infra` owns cloud resources and runtime wiring. It must be able
to deploy images produced from `../makersbrain` and the Odoo image containing
this repository's addons without reading application internals.

Application repositories must publish:

- immutable OCI image digest and software bill of materials;
- database schema release and compatibility range;
- required environment variable names, never values;
- health/readiness endpoints;
- worker subcommands and queue names;
- declared ports, volumes and resource estimates;
- migration command and rollback compatibility statement;
- Rauthy client/redirect manifest schema;
- Odoo addon release and required module list;
- Paperless version and supported integration contract.

Infrastructure must provide:

- environment-separated network, PostgreSQL, object storage and secrets;
- Rauthy, control API, frontend and independently scalable worker Quadlets;
- a shared Odoo runtime pool and PostgreSQL cluster, with one opaque database
  and filestore namespace per workshop;
- isolated per-workshop Paperless application/database/document volumes and a
  shared persistent Redis service with per-workshop prefixes and ACLs;
- exact hostname routing and TLS readiness;
- encrypted paired backups for Odoo database/filestore and Paperless
  database/data/media;
- monitoring for API readiness, worker heartbeat age, queue depth, dead
  letters, reconciliation drift, backup freshness and Azure usage;
- canary rollout, pre-upgrade backup and previous-image retention;
- production/staging/development isolation already specified in the infra plan.

OpenTofu creates durable infrastructure but does not execute tenant lifecycle
jobs or application migrations. The deployment pipeline adopts a release;
Rust workers then reconcile tenant instances through explicit operations.

The first complete backend is a local Docker driver, not the current synthetic
fixture. It proves provisioning, reconciliation, routing and recovery with real
resources. Production uses the `makersbrain-infra` Podman Quadlet/systemd
model. Keep both backends behind the same authenticated driver API and express
the same image, command, health check, environment and volume contract.

## 13. Reliability, backup and lifecycle

There is no distributed transaction across Rauthy, Odoo and Paperless. The
control database transaction records desired state and a durable operation;
workers converge each target. Every external call carries an idempotency key
where supported and is followed by observation where it is not.

Backup and restore are paired by tenant:

- Odoo PostgreSQL database plus filestore;
- Paperless PostgreSQL database plus data and media volumes;
- control-plane records required to resolve the tenant and external ids.

Shared Redis is operational queue state, not part of a tenant recovery set.
The driver blocks new tenant work, drains or records its prefixed queue state,
and stops that Paperless application before backup or restore. Redis itself is
backed up and monitored as a shared service; restoring one workshop must never
replace the shared Redis dataset.

The tenant hostname is `<workshop-slug>.<tenant-domain>` with no Odoo service
prefix. It is never used as the physical Odoo database identifier. Physical
names are opaque, and an exact deployment-gateway record maps a registered
hostname to one anchored database filter on the shared Odoo runtime. The
gateway strips any client-supplied database-selection header before inserting
its own value; Odoo is not directly reachable, runs with `list_db = False`, and
loads the reviewed header-filter integration as a server-wide module. Database
copies remain non-routable unless a separate, audited tenant-provisioning
workflow promotes one; restore and duplicate are owner-only and require typed
slug confirmation.

A restore drill must prove that Paperless document ids/content digests still
resolve to the correct Odoo draft bills. Restoring one side alone creates a
visible reconciliation incident.

Suspension, cancellation, user removal, ownership transfer, export, tenant
deletion and GDPR erasure are separate commands. Tenant deletion progresses
through restricted access, final export, backup, quarantine and retention
expiry. It never begins from a failed payment webhook directly.

## 14. Observability and audit

Propagate a UUID correlation id from the browser through API, operation,
worker and downstream request. Record structured metrics for request latency,
queue age, attempts, provider latency, reconciliation drift, invoice pages,
capture outcomes and backup age.

Audit events are append-only and answer: who requested what, under which
workshop authority, against which stable target, at what desired epoch, and
with what result. Redact authorization headers, cookies, invitation tokens,
invoice contents and provider responses before tracing sees them.

Operator dashboards show safe failure classes and retry state. Detailed secret
or document payloads are never an observability feature.

## 15. Delivery plan and gates

### Phase 0 — extraction baseline

- Pin and inventory reusable `../makersbrain` code and tests.
- Remove obsolete business-domain routes from the control-plane composition.
- Introduce explicit crates for domain, persistence and external adapters.
- Preserve generated OpenAPI, permission coverage and database privilege tests.

Gate: the Rust API and existing identity/email workers build and their retained
tests pass with no Odoo, Paperless or Azure dependency.

### Phase 1 — identity and Members slice

- Extend roles and membership schema.
- Finish artisan-scoped Members UI.
- Implement invite/accept/resend/revoke, role change, removal and ownership
  transfer.
- Reconcile a fixture Rauthy, Odoo and Paperless target through workers.

Gate: one invited person signs into Odoo and Paperless with the same Rauthy
subject; removal denies both while preserving history; retries create no
duplicate users.

### Phase 2 — tenant provisioning

- Add service-instance, domain and operation-step records.
- Keep the fixture for contract tests, then implement the authenticated Docker
  deployment driver and persistent idempotency ledger.
- Provision opaque databases and filestore namespaces on shared Odoo, isolated
  Paperless applications/storage, shared-Redis prefixes/ACLs, OIDC clients,
  exact gateway routes and the initial owner.
- Add a strict file-backed development secret resolver so dynamically created
  tenant credentials never enter the control database or operation payloads.
- Add health, drift and repair views.

Gate: a fresh workshop reaches ready state from one command; killing the worker
or Docker driver after every step and retrying reaches the same single tenant.
Two workshops must use the same Odoo and Redis processes while retaining
different Odoo databases, filestore namespaces, Paperless instances, Redis
prefixes and credentials.

### Phase 3 — invoice capture

- Implement Paperless events, document retrieval and revision identity.
- Add Factur-X/CII and UBL detection before OCR.
- Add Azure adapter, normalization, metering and limits.
- Implement and test the Odoo `mb_invoice_capture` receiver/review surface.

Gate: a scan/photo creates one balanced draft bill; structured invoices make
zero Azure calls; replay is a no-op; low-confidence or inconsistent documents
require review.

### Phase 4 — infrastructure integration

- Add image/runtime manifests consumed by `makersbrain-infra`.
- Deploy development, then staging with Quadlets and Infisical identities.
- Add paired tenant backup/restore, monitoring and canary release controls.
- Run negative isolation and secret-leak tests.

Gate: staging can provision, upgrade, suspend, restore and reconcile a tenant
without manual database edits or secrets in logs/state.

### Phase 5 — production readiness

- Load and failure test API and queues.
- Exercise Rauthy outage, Azure throttling, Paperless downtime, Odoo upgrade
  failure and unknown provider outcomes.
- Complete retention, recovery, ownership and support runbooks.
- Rehearse a production-like release and rollback from immutable images.

Gate: all acceptance criteria below have retained evidence and named owners.

## 16. Acceptance criteria

- A workshop owner can invite and remove members without access to Rauthy
  Admin or raw application groups.
- One verified Rauthy subject enters the correct tenant Odoo and Paperless
  clients; it gains no authority in another workshop.
- Ownership transfer cannot remove the last owner and is not achievable through
  ordinary role editing.
- Provisioning and membership changes survive worker termination and replay
  without duplicate tenants, users or invitations.
- Revocation is effective in the control plane immediately and converges in
  Odoo and Paperless with visible retry state.
- A scanned image or phone photograph produces at most one reviewable draft
  supplier bill, with source and extraction provenance retained.
- Factur-X/CII and UBL bypass Azure; Azure pages are metered per workshop and
  bounded by plan limits.
- No OCR result can post/pay a bill or silently create accounting master data.
- Cross-workshop Odoo, Paperless, job and backup access is denied by automated
  negative tests.
- A forged Odoo database-filter header is overwritten by the gateway, and one
  Paperless Redis identity cannot read, publish to or consume another
  workshop's prefix.
- No human password, Rauthy admin key, Azure key, Paperless token, invoice body
  or invitation token appears in application databases, logs or OpenTofu state.
- `makersbrain-infra` can deploy and roll back immutable API, worker, frontend
  and tenant images using only their published runtime contracts.
