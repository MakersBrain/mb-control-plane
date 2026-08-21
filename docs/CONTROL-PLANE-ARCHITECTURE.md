# MakersBrain control-plane architecture

Status: current state
Last verified: 2026-08-14
Normative scope: `control-plane/`, `addons/mb_control_bridge/` and the local
deployment contract consumed by `makersbrain-infra`

This document describes the implementation that exists in this repository. It
does not describe intended release-management or production-hardening work;
that belongs in `CONTROL-PLANE-ROADMAP.md`.

Accepted architecture decisions are recorded under
`docs/adr/`.

## 1. Boundaries

The control plane owns workshop identity and authority, desired service state,
durable operations, deployment-driver commands, capability activation, paired
Odoo/Paperless recovery, extraction admission and the artisan/operator web
application.

Odoo owns workshop business records. Paperless owns source documents. Rauthy
owns human credentials and sessions. The extraction broker owns provider
credentials and normalizes provider responses. The infrastructure repository
owns production placement, host identities, networking and the future
Podman/systemd driver.

Catalogue synchronization, the scraper webservice, supplier acquisition and
proxy configuration are outside this architecture. They integrate only through
their existing contracts.

## 2. Executable topology

The local Compose topology contains:

- `control-api`: Axum HTTP API, authentication and command admission;
- nine single-queue `control-worker` processes: tenant provisioning,
  membership provisioning, invoice capture, inventory capture, email delivery,
  tenant reconciliation, tenant lifecycle, release adoption and privacy
  operations;
- `control-migrate`: one-shot SQLx migration runner;
- `control-backup-scheduler`: periodic portable backup and restore rehearsal
  admission;
- `control-docker-driver`: authenticated development deployment driver with a
  persistent idempotency ledger;
- `document-extraction-broker`: private provider boundary;
- `control-web`: SvelteKit artisan and operator frontend;
- shared PostgreSQL, Rauthy, Redis, Odoo and exact-host tenant gateway services;
- dynamically created Paperless containers and tenant resources.

`deploy/release-contract.json` is the machine-readable process,
queue, image and environment contract. Compose is a local development
implementation, not the production runtime design.

The worker dispatcher owns leasing, heartbeats and terminal outcome mapping.
Dedicated private modules own email delivery, release adoption, privacy work,
lifecycle/recovery behavior, and invoice/inventory extraction. The lifecycle
module contains restore fencing, erasure replay, recovery-component persistence
and terminal state repair. The extraction module contains provider throttling,
usage reservation, normalized checkpoint handling and tenant-bound delivery.
Neither module owns queue admission or provider credentials.

## 3. Tenant model and routing

One workshop maps to one opaque Odoo PostgreSQL database named `mb_<uuid>`.
Workshop slugs and hostnames are never database identifiers. A shared Odoo
runtime serves all databases. The gateway discards any client database header
and writes the exact database mapping registered for the requested host. Odoo's
database manager/list is disabled and the server filter accepts only opaque
identifiers.

Paperless is process- and database-isolated per enabled workshop. Each process
has dedicated persistent volumes and a distinct shared-Redis ACL identity with
key and channel prefixes. Its long-lived container mounts only the workshop's
`paperless-runtime` subpath from a driver-only secret volume that API and worker
containers do not mount. Native `_FILE` settings keep its
database, Redis, Django, OIDC and admin credentials out of Docker metadata, and
post-consume events authenticate with a workshop-bound bridge credential rather
than the global internal API token.

Worker-facing integration credentials are separated again: the tenant volume
contains a distinct high-entropy Odoo bridge token per workshop, while a
dedicated read-only Paperless client volume is mounted only by the membership
and invoice workers. Odoo stores only the token's SHA-256 verifier in the
selected tenant database. Neither worker-facing volume exposes Paperless
infrastructure credentials.

Fresh provisioning uses the process bootstrap credential for the single
initial tenant-bootstrap request that installs the new tenant verifier. A retry
with an already-created tenant credential authenticates directly as that
tenant; authentication failures are never retried with the process credential.

Application releases are immutable, signed manifest records with image,
source, addon, schema-epoch and directional-compatibility evidence. Tenant
adoptions, fleet fences, blue/green runtime slots and immutable activation
intents prevent a shared-runtime switch until the fleet is prepared. Initial
provisioning requires the active application release and records an active
tenant adoption; backups resolve their source from adoption history rather
than a process package version. Provisioning is held while a fleet fence is
unfinished.

## 4. Identity and authorization

Rauthy is the human identity provider. The API verifies OIDC tokens, links an
immutable `(issuer, subject)` to one internal user and reads workshop authority
from control PostgreSQL for each request. Workshop roles are viewer, artisan,
accountant, studio manager and owner. A deferred database trigger prevents the
last active owner from being removed.

Platform authority is stored as versioned technical-administrator, release,
privacy, security and audit role assignments. `CONTROL_OPERATOR_EMAILS` is a
one-time initial technical-administrator bootstrap and cannot grant authority
after bootstrap closes. Sensitive grants, revocations, deletion, restore,
retention and fleet actions require recent strong OIDC authentication. A
separately registered production operator OIDC client remains an infrastructure
deployment requirement.

## 5. Control data and operations

One curated base migration creates the control schema. Principal records
include users and external identities, workshops and memberships, invitations,
service instances, desired membership targets, ownership transfers,
entitlements, capability state, usage reservations/counters, the email outbox,
audit events, Odoo database lifecycle, recovery sets/rehearsals, retained
deletion state, product lookup cache and durable operation checkpoints.

External mutations run as durable operations. Operations have one named queue,
bounded attempts, due time, leases, heartbeat renewal, fencing by worker and
attempt, safe failure classes, dead letters and an explicit
`awaiting_reconciliation` state for unknown external outcomes. The Docker
driver records action IDs and results in its own persistent ledger.

All persisted public lifecycle mutations use centralized RFC 8785 command
admission, identical replay and payload-mismatch rejection. Mutable resources
use strong version ETags and compare-and-set writes. Identity linking is the
pre-authentication, intrinsically idempotent exception; validation and download
capability responses do not mutate control state.

Public route declarations own their handler, method and security classification
once. The same declarations construct the Axum router and OpenAPI path set, so
the executable contract no longer depends on a duplicated list or source-text
regex. Public mutation responses use closed schemas, including explicit replay
and in-progress variants; downloads declare binary media and versioned writes
declare their ETag response. Generated TypeScript models are checked for
freshness against the executable OpenAPI document, whose success statuses are
limited to responses the handlers can return.

## 6. Secrets and process privileges

The migration process owns the control schema. The API, each worker class, the
backup scheduler and the development driver ledger use distinct non-owner
PostgreSQL logins with migration-managed grants. Local Compose passes only
bounded `@/run/secrets/...` references and mounts each provider/database secret
into the processes named by the exact runtime-environment matrix; a rendered
configuration canary gate detects value interpolation. The email and lifecycle
workers do not mount tenant secrets. Credential issuance and rotation are
defined in `docs/database-identities.md`.

Dynamic Docker jobs receive per-job UUID volume subpaths. PostgreSQL password
files, Odoo bridge/runtime credentials, S3 access keys, age recipients and
encrypted-manifest inputs therefore remain outside Docker `Env` and `Cmd`
values. Atomic writes, post-job deletion, fail-closed stale-secret cleanup and a
source canary guard this boundary.

Long-lived Paperless and release-runtime secrets use versioned, read-only
subpaths in the driver-only volume. Their configuration digests include the
secret-boundary version and source volume, so a mount-layout change replaces
the container before an obsolete runtime path is discarded.

Every release executable validates its complete process-specific environment
against the embedded `configuration-spec.json` before opening a listener or
starting queue work. Missing values and placeholder secrets fail startup; the
privacy worker additionally refuses reuse of one key for lookup and export
encryption. CI proves every release entrypoint is bound to this gate.

Planned export-key rotation keeps only still-live previous keys in an optional,
API-only decryption key ring. The ring is bounded to 16 keys and 64 KiB, cannot
contain the active encryption key, and each entry is removed no later than the
seven-day export expiry. New artifacts always use the active key. A suspected
compromise never uses this overlap: the affected key is revoked and outstanding
exports are recorded and reissued.

The Docker driver is the only writer of tenant secret files. A separate
privacy-driver credential exposes only the authenticated subject-export route;
the privacy worker receives neither the deployment credential nor the tenant
secret root. Tenant bootstrap also runs inside the idempotent provisioning
driver operation, so the provisioning worker receives only its driver token
and never mounts tenant integration credentials. The backup helper
receives portable-backup credentials and age material; application workers do
not. The Docker driver refuses any environment except explicit development and
is the only component that mounts the socket. Production must supply the same
authenticated contract through the infrastructure Podman/systemd driver and
approved secret resolver before accepting customer data.

Inside the development driver, raw Docker Engine exec, container and volume
calls are isolated in a private transport module. Release, recovery and tenant
orchestration consume that boundary and do not construct Docker HTTP requests
directly. PostgreSQL database administration and short-lived PostgreSQL job
containers form another private adapter with strict opaque-identifier checks.
Fleet release preparation, isolation, upgrade verification, retained runtime
handling and atomic route activation form a dedicated orchestration module on
top of those transports.

Recovery lifecycle fencing, local and S3 recovery sets, encrypted manifests,
restore validation, Paperless archives and erasure replay form a dedicated
recovery module. Redis ACL, Rauthy/OIDC, Odoo and Paperless provisioning live in
a tenant-service module. Exact-host route generation, atomic gateway reload and
read-only restriction enforcement live in a gateway module. The driver root is
therefore limited to configuration, authenticated/idempotent dispatch, tenant
provision composition and shared filesystem/job primitives.

## 7. Invitations and audit

Invitation rows store generation and expiry state but no usable capability.
Generation-pinned outbox events contain only non-secret signing metadata. The
email worker constructs an Ed25519 compact JWS and fragment-delivered acceptance
URL in memory after proving the event is still current. The API has public
verification keys only; validation and acceptance receive the token in a POST
body. The fresh base schema contains only generation-pinned invitation and
outbox contracts; no earlier link format is accepted.

Audit events are inserted alongside commands and are not exposed with secret
payloads. A database trigger rejects every audit-row update or delete, and the
CI role-matrix proves runtime identities cannot mutate them.

## 8. Capabilities and extraction

The versioned capability registry maps user-visible bundles to internal Odoo
modules and optional services. Migration startup materializes the signed
embedded registry as immutable `(registry_version, capability_key)` entries;
workshop activation pins the registry, application release, entitlement version
and resolved implementation. It includes ceramics workflow, dependency edges,
kiln/firing requirements, entitlement and active-tenant-release checks, and a
database-enforced activation state machine. The JSON registry digest, Rust
definitions and PostgreSQL entries are checked against the release contract.
The tenant-reconciliation worker continuously compares every enabled capability
with its pinned active entitlement and tenant release. Drift first moves the
capability to fail-closed `restricting`, then invokes its allowlisted adapter:
Odoo write rules for addon-owned models, a read-only Paperless gateway policy,
or the existing control-API gate for broker capabilities. Historical reads stay
available, and the database accepts `restricted` only with non-empty enforcement
evidence; adapter failure remains visibly `restricting` and cannot reopen access.

Invoice and inventory capture are admitted per workshop. Provider credentials
remain inside the extraction broker. Structured invoices can be processed
locally. Usage reservations, rate limits, normalized responses and safe errors
are persisted without source document bodies in control PostgreSQL.

## 9. Recovery

Workshop lifecycle operations serialize snapshots, encrypted portable backups,
restore and non-routable duplicate creation. A recovery set pairs the Odoo
database and filestore with Paperless database and volumes when Paperless is
enabled. Destructive restoration first creates a safety recovery point.

The scheduler admits periodic portable backups and isolated restore rehearsals.
Production object lock and PITR remain infrastructure gates. Erasure tombstones
are idempotent and workshop-scoped. A restore predating a tombstone stays behind
a maintenance route while a lifecycle worker decrypts its tombstone-bound
processor lookup, invokes idempotent Odoo and Paperless anonymization through
the tenant-scoped deployment driver, and records every restored location in a
durable replay ledger. The driver refuses to resume routing until that ledger
is complete. Missing keys, lookup data or acknowledgements fail closed.
Retained quarterly production disaster-recovery evidence remains required.

## 10. API, UI and observability

The API exposes health, identity, workshop, membership, invitation, capability,
integration, recovery, operation, internal event and platform-operator routes.
Recovery handlers and their lifecycle serialization helpers live in a private
API module; deletion, release adoption and capability activation share only its
crate-internal locking primitives. This keeps recovery state transitions out of
the general transport composition layer. Workshop, invitation, membership and
ownership-transfer handlers form a second private authority module; shared
command admission and append-only audit helpers remain in the API composition
layer. Platform operator views, workshop repair/deletion and application-release
publication/adoption form a third module, separate from member-facing authority.
Processor-facing Paperless events, inventory capture/lookups, cache-fill leases,
tenant reconciliation and entitlement acknowledgements form a fourth private
internal module excluded from the browser contract.
`openapi.json` describes every public router operation, and a source-parity test
fails on route or method drift. Deterministic operation IDs and command-header
semantics generate the browser fetch client during CI. Every response consumed
by the browser—including identity, workshop, membership, invitation,
capability, recovery, release, platform and privacy views—is typed once in Rust
and reused by the web application. Mutation request bodies are derived from the
same Rust inputs, bodyless commands advertise no fictional payload, and the
bounded operator query parameters are explicit. Public responses not consumed
by the browser still need the same treatment. CI regenerates the browser client
and rejects generated-source drift. The retained bridge integration lane checks
the current control-plane client against the current external Odoo provider.

Structured JSON logs, durable worker heartbeats, privacy-safe HTTP counters and
latency sums, queue/dead-letter/lease metrics, release adoption status, backup
and restore-rehearsal freshness, fleet views, Prometheus alert rules and
operator runbooks exist. Bounded Odoo, Paperless and Rauthy health series make
processor availability alertable without tenant labels. The private document-extraction broker additionally
exports authenticated provider request and latency sums with bounded,
privacy-safe labels. Every executable supports opt-in OTLP/HTTP traces with a
stable service name; exported spans are limited to templated HTTP routing and
internal durable-operation attributes, and uncontrolled log events are never
exported. W3C trace parent/state fields continue the span through durable queue
storage without copying headers, tokens or request payloads.

`CONTROL_DATA_MODE` is explicit. Synthetic development is allowed locally; in
personal mode the mandatory pre-migration process refuses to complete until
bounded evidence references identify the controller, processing record,
retention approval, processor register and DPIA approval, and the exact region
is Paris, Azure France Central or Azure West Europe. Every active application
processor—including Rauthy, Odoo, extraction, workers, driver and gateway—has a
successful-gate dependency. PostgreSQL and Redis may start as passive storage,
but the processing topology cannot start. Approval is an external governance
action and cannot be self-issued through the blocked deployment.

## 11. Verification

CI runs Rust formatting, strict Clippy, unit tests, clean PostgreSQL integration
tests, the runtime role matrix, Svelte checks/builds, contract/link/privacy
inventory validation, addon validation, translations and Odoo server/browser
suites. Release and GDPR state-machine coverage is present. Provider adapter
tests lock the shared HTTP failure taxonomy and critical Rauthy, Odoo and
Paperless outcomes, including authorization failures, throttling, unavailability,
contract drift and idempotent absence where applicable. The two-workshop
full-topology, failure-injection, secret-canary and retained production recovery
rehearsals remain future gates.

## 12. Privacy operations

The machine-readable inventory, Article 30 processing-record draft, retention
policy, processor register and DPIA record deliberately keep production
personal data blocked while the legal controller and approvals are unknown.
The deployment preflight and versioned database records both enforce the
production gate. Privacy reviewers manage rights decisions, scoped legal holds
and processor evidence; security responders record incident discovery,
controller awareness and assessments with the calculated 72-hour deadline.

Retention is a durable dry-run/live operation and refuses live deletion without
an approved policy containing explicit durations. Scoped holds exclude only
matching datasets, workshops and subjects. Rights requests cover access,
rectification, erasure, restriction, portability and objection, with controller
review, deadlines, processing holds, processor tasks and idempotent erasure
tombstones. Automatic restore replay has Odoo and Paperless adapters and a
maintenance fence, but ordinary data-subject completion still requires explicit
processor acknowledgements. Encrypted single-use access/portability exports
combine control-plane records with tenant-bound Odoo records, related
attachments, Paperless account and OCR metadata, and original documents.
Processor bodies bypass control PostgreSQL and are immediately encrypted into a
dedicated private artifact volume; download verifies AEAD and SHA-256 integrity,
then consumption or expiry deletes the file. Planned key rotation preserves
only the decryption ability needed by still-live artifacts; compromise rotation
invalidates and reissues them. Additional production processor
adapters and retained live-topology evidence remain deployment gates.

## 13. Normative references

- `deploy/release-contract.json`: executable release contract;
- `deploy/compose.yml`: local topology;
- `migrations/`: current control schema;
- `src/domain.rs`: operation kinds and queues;
- `BACKUP-RESTORE.md`: current recovery procedure;
- `CONTROL-PLANE-ROADMAP.md`: status, gates, principles and open decisions.

## History

The control plane was extracted from `../makersbrain` into this repository; the
proposal that described that extraction, and the improvement programme that
turned the result into a release-managed platform, are both complete. Their
remaining gates live in `CONTROL-PLANE-ROADMAP.md` and their superseded
specifications remain available in Git history.
