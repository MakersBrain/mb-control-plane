# MakersBrain control-plane architecture

Status: current state
Last verified: 2026-08-14
Normative scope: `control-plane/`, `addons/mb_control_bridge/` and the local
deployment contract consumed by `mb-infra`

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
unfinished. Shared-runtime release effects are additionally serialized across
driver replicas by a PostgreSQL lease whose monotonic fence is carried through
the fleet run, activation intent, driver receipt, and worker finalization.
Release execution renews that exact lease at phase boundaries and from a
structured background heartbeat. Losing renewal cancels the in-flight effect
future and quarantines the authority as outcome-unknown; completing the effect
cancels the heartbeat before exact fenced finalization.
Every shared-Odoo release request first acquires one driver-owned, cross-process
host lock without holding a database transaction. The lock file rejects
symlinks, unexpected owners or modes, hard links, and descriptor/path identity
changes. The RAII guard remains held from before database admission through the
exact driver-receipt transition, so process exit, cancellation, and unwinding
release host authority and cooperating driver processes cannot overlap.
PostgreSQL fencing remains the durable publication authority; the host guard
is not evidence that a request already accepted by Docker, systemd, or
PostgreSQL has terminated. Automatic fleet reconciliation therefore requires
exact external-executor termination and observation.
New protocol-v1 fleet upgrade jobs carry the exact fleet run, driver operation,
original fence and adoption identity as closed runtime labels. Their Odoo
connections use a bounded application name derived from that complete identity,
while direct administrative PostgreSQL connections carry the driver-instance
UUID retained by quarantine. Read-only Docker/Quadlet and `pg_stat_activity`
observers can therefore distinguish active, terminal and ambiguous executors.
Missing runtime objects count as absence evidence only for protocol-v1 jobs;
legacy untagged operations remain quarantined. These observers never kill or
roll back an executor and do not by themselves authorize reconciliation.
Expired or outcome-unknown execution quarantines the resource; it is never
automatically stolen because the underlying Docker, filesystem, routing, and
database adapters cannot enforce the database token themselves.
Migration 0018 adds a bounded exception for initial preparation while the fleet
is still provably empty. A fresh, expiring reconciliation claim may inspect the
exact prepared slot's named Docker runtime without replaying effects; only an
exact image, config, read-only extension mount, operation ID, and original fence
match converts the original receipt to success. Finalization re-authenticates
the exact upstream operation lease and holds the empty-fleet tables against
concurrent writes while rechecking that predicate through commit. Missing or
mismatched evidence stays quarantined. Fleet activation is excluded because its gateway, database
grant, and old-runtime effects require a cross-fence compensation protocol.
Fleet activation now embeds a closed versioned identity in the selected Nginx
generation and reads it back from a loopback-only endpoint in the running
worker. The exact fleet run, driver action, original fence, gateway digest, and
target slot must match before the activation intent records its observed digest
and timestamp. Legacy intents without identity protocol version 1 remain
non-reconcilable. Migration 0023 adds a function-only, expiring reconciliation
claim for a protocol-v1 fleet executor which entered outcome-unknown
quarantine. Admission binds the original driver operation, host instance,
fence, fleet run, activation intent, loaded-gateway identity, request digest,
and current release-worker attempt. Reacquiring an expired claim records the
expiry and stale tokens cannot finalize. Success accepts only a closed
forward-only proof that the prior executor is quiescent, the candidate runtime
and exact loaded gateway identity are verified, target database access is
correct, and the old runtime is retired. It may atomically acknowledge that
exact version-1 activation intent and convert the original receipt to success;
inconclusive observation leaves quarantine intact. No database capability
exists to replay route effects, restore the old generation, regrant the old
runtime, abandon the intent, or turn an ambiguous fleet operation into failure.
During rolling deployment the prior 11-argument release-admission signature
remains available, but it intentionally records a NULL executor protocol.
Those releases complete normally; an ambiguous old-binary outcome cannot enter
the automatic reconciliation path.

Gateway route files live behind one validated, driver-owned generation
selector. Nginx imports only `current/*.conf`; workspace boot atomically selects
a freshly emptied generation before Nginx starts; and every projection,
startup, recovery, and release route effect resolves that same local selector.
Migration 0024 adds the database half of staged startup publication on this
boundary. Admission freezes the complete route set plus shared-runtime facts;
a function-only child ledger exposes at most 500 rows from a durable cursor;
candidate CAS transitions seal only when the frozen IDs still equal the entire
current route-lease fleet. The selector may be exchanged only after the seal,
and applied heads advance only after the running gateway reports the exact
effect-run ID and sealed digest. Expired publication-started work is
quarantined and can be completed or restored only through an expiring exact-
observation reconciliation claim. The prior 0019 APIs remain during the rolling
Rust cutover but do not manufacture protocol-v1 reconciliation evidence.

Migrations 0025 and 0026 also stage a dormant protocol-v2 release route
boundary. The first freezes the exact fleet projection snapshot; the second
binds it to the upstream worker attempt, driver/global lease, target slot, and
one fenced `release-overlay` authority per workshop. Function-only transitions
record and seal immutable maintenance and candidate generations, then require
the exact loaded-gateway identity. Candidate observation advances only the
frozen applied route heads and stops at `awaiting_worker_finalize`, retaining
all release and route authorities. No active Rust release path invokes this
state machine, and the schema exposes no whole-release success or rollback;
activation and finalization remain later cutover work.

Migrations 0027 through 0031 add a second, still-dormant projection-only
route-set protocol. Admission freezes the full fleet, transition functions
seal and publish immutable generation evidence, and normal finalization uses a
full-fleet applied-head CAS. Interrupted work is quarantined behind a separate
fenced reconciliation claim. A reviewed terminal decision is bound to the
immutable observation, claim capability digest, reconciliation operation, and
canonical decision digest: candidate recovery advances only the target head;
prior or unstarted recovery records a non-applied terminal result; inconclusive
evidence remains quarantined. Terminal receipts replay without reacquiring
reusable live leases, while the public result reader returns recovered terminal
outcomes instead of leaving callers pending. No active Rust call site or schema
activation API enables this protocol.

Migrations 0032 through 0034 close the flat-writer boundary and extend that
universal ledger to dormant recovery-maintenance and fleet-scoped startup
publications. Startup has no synthetic target workshop or control operation:
one startup effect owns the frozen fleet, shared-runtime evidence, global
authority, and every route authority. A genuinely uninitialized route may
carry a nullable applied baseline, while `BootLive` is accepted only as exact
startup prior evidence. Admission caps the fleet at 500 before mutation and
completion advances all frozen heads in one transaction after exact six-key
loaded identity. Startup-specific reconciliation restores each pre-start lease
state for prior or unstarted evidence, completes forward only for an exact
post-start candidate, and leaves ambiguity quarantined. Readiness and active
production dispatch remain unchanged; shared retention-ledger integration is
implemented by migration 0035 as a dormant, separately fenced boundary. It
retains the newest two exact candidate observations and every generation still
referenced by unresolved publication evidence. PostgreSQL commits one global
retention claim before filesystem work, but deletion additionally requires the
shared host guard and a fresh descriptor-relative proof that the stable
selector is not the target. Legacy startup and release artifacts remain out of
scope in 0035, and no readiness or production callsite is enabled.

Migration 0036 completes only the dormant protocol-v2 release driver's route
publication close. After the exact candidate has been observed, one fenced
transaction stores the existing release response, succeeds the driver receipt,
releases the global and complete frozen route authority set, and marks the
publication completed. The release worker still performs the established,
separate tenant/runtime/release/fleet-run activation transaction from that
succeeded receipt; 0036 deliberately does not duplicate it. An immutable
completion row and read API make a committed close replayable after network
ambiguity. Release recovery, release-generation retention, readiness, and
production dispatch remain outside this tranche.

Migration 0037 adds the dormant, release-specific interrupted-publication
recovery boundary. A new live release-adoption attempt authenticates each
expiring fenced claim; immutable authorizations precede any selector exchange,
and immutable resolutions bind exact filesystem observations. Pre-external
prior/unstarted decisions close as typed `not_applied`, while post-external
recovery is forward-only through the exact candidate and the same 0036 runtime
response proof. The protocol remains uncalled and does not change readiness.

Migration 0038 extends that retention discipline to terminal protocol-v2
release overlays. Immutable maintenance and candidate subjects are
materialized atomically from a normal or recovered completion; a successful
pre-external prior restoration materializes only its published maintenance
subject, while cleanup and unstarted recovery manufacture no artifact. The
newest two applied candidates are protected across both the universal and
release ledgers, and every unresolved startup, universal, or release selector
reference remains ineligible. Each artifact has a separately fenced claim and
immutable terminal evidence. PostgreSQL authorization still precedes and does
not replace the shared host guard, exact directory identity, repeated current-
selector exclusion, and descriptor-relative one-child deletion steps. The
typed Rust coordinators remain private to the driver. A compile-verified,
dormant scheduler now provides bounded keyset discovery across both retention
ledgers: it alternates lanes, processes at most one filesystem effect at a
time, caps each epoch, and resets cursors between epochs. Capacity contention
does not advance the cursor or lose the candidate; transient and protocol
failures use capped jittered backoff. Release compound cursors use an explicit
`candidate`-before-`maintenance` ordinal in both SQL and Rust rather than
database collation. The scheduler has an explicit supervisor registration seam
but no production call site, so polling and protocol activation remain absent.

Migration 0039 adds the first read-only input required to reconstruct an
interrupted forward-only release candidate. The current fenced recovery claim
can read the immutable protocol-v2 snapshot in UUID-keyset pages, but only
while the publication is quarantined at `candidate_staging`. Each page is
revalidated against the immutable snapshot header, publication owners, and the
claim's frozen route heads. Explicit `complete`, `claim_lost`, and `wrong_phase`
sentinels prevent an empty or unauthorized query from being mistaken for end
of scan. The driver adapter reuses the normal release snapshot validator, so
projection shape, target slot, digests, fences, and ordering have one policy.
Only `control_driver_ledger` receives execute permission; no role receives
direct table access. Runtime expectation/observation, completion receipts, and
the candidate-forward effect path are supplied by the later dormant recovery
composition; independent terminal review and production dispatch remain
absent.

Migration 0040 adds a claim-authenticated runtime-expectation boundary without
turning database state into runtime evidence. It returns the exact release
manifest, operation/fleet/fence/slot identity, tenant sets, and gateway intent
only while the forward-only publication and quarantined global authority still
match. Container names, secret-derived configuration digests, restart policy,
mount state, database access, readiness, and loaded gateway identity must still
be observed independently by the driver. The typed Rust adapter validates the
closed response and emits only operation ID and outcome tracing fields. The
migration also disables the unsafe `unstarted` resolution and refuses a
BootLive prior without a positive loaded identity. A private compatibility
primitive preserves the audited 0037 implementation, a typed wrapper gates new
calls, a `NOT VALID` constraint guards new direct writes, and the finish wrapper
prevents historical unsafe rows from terminalizing. All recovery dispatch and
external effects remain dormant.

Migration 0041 adds the complementary immutable runtime receipt and an
independently privileged review boundary. The deployment driver records only a
closed set of live runtime facts under the exact recovery claim; PostgreSQL
joins those facts to the 0040 expectation and constructs the canonical 0036
completion response itself. Candidate authorization and resolution load that
stored response and reject caller-supplied substitutes. After exact route
observation, only the release worker may bind the runtime-observation digest to
the database-derived route-resolution digest and accept the candidate. The
driver can then finish from that accepted review without supplying either a
response or decision digest. Both receipts are immutable and replay-safe,
their tables have no runtime-role data privileges, and private compatibility
primitives have no runtime execute grants. The typed Rust adapters use closed
outcomes, strict response validation, and tracing that records only safe
operation identity and outcome fields. A private dormant coordinator now
composes the bounded snapshot, immutable candidate seal, opaque runtime receipt,
database-issued exact publication authority, guarded selector publication,
gateway reload, and opaque post-publication route proof. It renews the claim
around external effects, reopens an exact sealed generation after the
filesystem-before-database crash window, and stops at an
`AwaitingIndependentReview` handoff. The adapters and coordinator remain
private with no scheduler or production call site, so 0041 still does not
activate recovery effects.

Runtime evidence now has one Rust provenance boundary as well. The private
`release_runtime_observation` module owns the only constructor for a verified
observation and performs read-only checks across the original driver and
per-tenant executors, candidate and retained runtimes, restart/boot policy,
exclusive database access plus credentialed identity, tenant release identity,
one-shot readiness, route bytes, and the loaded rolling gateway identity. The
existing protocol-v1 fleet reconciliation uses this observer, while the 0041
receipt adapter accepts only its opaque result; sibling modules can no longer
manufacture positive evidence booleans. Filesystem/runtime mutations, claim
renewal, timeouts, and receipt writes remain outside the observer. Its active
async path loads the runtime credential, exact workshop-keyed bridge
credentials, selected-generation validation, and every bounded route file in
one `spawn_blocking` filesystem snapshot behind a private read-only port.
Secrets have no debug or serialization surface, tenant-key parity is checked
before use, and readiness/network/database checks consume the preloaded
snapshot rather than blocking a Tokio worker per tenant. A dormant
recovery constructor projects the exact 0040 expectation into the same policy;
failure to observe the rolling identity remains inconclusive, while exact
protocol-v2 candidate identity is intentionally reserved for post-publication
route resolution and review. Recovery database/review spans also parse outcomes
before recording them, map malformed responses to the closed
`contract_drift` label, and exclude workshop identity and evidence details.
The adjacent route-set recovery adapter follows the same parse-before-record
rule. Its typed outcome vocabulary also follows the authoritative migration
literal `unsupported_resolution`; the obsolete, non-SQL
`unsafe_resolution` spelling fails closed as contract drift.

The deployment driver nevertheless owns the prerequisite asynchronous lifecycle
now. A bounded actor supervises dormant publication, recovery, startup, and
retention roots, continuously reaps them, and admits cleanup during drain only
through a capability issued to an already-owned root. Singleton long-lived
services are owned and measured separately from effect admission capacity;
drain synchronously signals each service before joining it with all roots and
descendants. A service exit before drain, including an apparently clean exit,
is fatal and closes admission rather than leaving a ready process without its
scheduler. The actor's admission state is also the readiness drain gate.
Signal handling closes that gate before Axum's graceful HTTP shutdown, then
joins all owned work while retaining the driver pools and runtime clients.
Panic, unexpected cancellation, or a closed task failure makes shutdown fail;
safety cleanup is never aborted by an internal timeout. This lifecycle
foundation and the dormant retention service seam do not enable polling,
generation-v1 readiness, or publication dispatch.

## 4. Identity and authorization

Rauthy is the human identity provider. The API verifies OIDC tokens, links an
immutable `(issuer, subject)` to one internal user and reads workshop authority
from control PostgreSQL for each request. Workshop roles are viewer, artisan,
accountant, studio manager and owner. A deferred database trigger prevents the
last active owner from being removed.

Platform authority is stored as versioned technical-administrator, release,
privacy, security and audit role assignments. `CONTROL_OPERATOR_EMAILS` is a
one-time initial technical-administrator bootstrap and cannot grant authority
after bootstrap closes. Platform mutation transactions share-lock the actor's
current active grants and re-evaluate the route-authorized permission before
admitting a command, so concurrent revocation cannot create a stale-authority
write. Sensitive grants, revocations, deletion, restore, retention and fleet
actions require recent strong OIDC authentication. A
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

Fleet privacy retention is a database-owned, fixed-size capability rather than
an unbounded worker query. A run freezes a cutoff and monotonic per-dataset
high-water marks once, persists phase cursors and evidence counters after every
batch, rechecks legal holds transactionally, and authenticates its exact live
operation attempt before mutation and completion. Concurrent rows beyond the
snapshot and held rows are deferred to a future run.

A generic
worker's handler and terminal compensation share one structured heartbeat
scope: renewal requires the existing exact lease to remain unexpired, lease
loss cancels the handler before further compensation or finalization, and
handler completion cancels the heartbeat before the exact terminal update.
Checkpoint and final writes authenticate the same unexpired tuple. Cancellation
cannot retract an outbound mutation already accepted by a provider; those
attempts still enter the operation kind's idempotent observation/reconciliation
path rather than assuming that dropping a Rust future undid the effect.

Periodic webshop-domain work is admitted by a bounded database claim that
atomically creates and tenant-binds each operation. Once leased, the feature
uses a transaction-only workshop capability, takes coherent repeatable-read
snapshots, commits before external I/O, and fences every result mutation to the
exact live attempt. The deployment driver validates the propagated attempt and
owner again immediately before runtime effects. Ambiguous Cloudflare create or
delete sends stay reconcilable. Route documents are complete-workshop
projections; a monotonic database generation and cross-replica driver lease are
used by every producer and the driver's `route-project` action to prevent two
independently valid operations from applying those projections out of order.
Migrations 0012 through 0015 persist immutable projections, present/absent desired
and applied heads, global and workshop fences, strict receipts, durable startup
and recovery effect runs, and quarantine. Fleet release and startup acquire the
global umbrella before the frozen SQL-derived workshop route set. Startup
rebuilds from immutable projections before readiness. Recovery enters a stable
maintenance state and exits by rendering the latest desired projection; it
never restores stale route-file backups. Lifecycle deletion applies an absent
tombstone before destructive effects. The domain table is still not marked
RLS-ready. Provider-deletion evidence and fair periodic admission are described
by migrations 0014 and 0015. The full route protocol is specified by
[`ADR 0009`](adr/0009-durable-workshop-route-projections.md).

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
URL in memory after proving the event is still current. Email startup validates
the exact private gateway route, trusted public origin and absolute signing-ring
path before telemetry, and builds one credential-safe HTTP transport for the
process. Each invitation reloads that validated ring so atomic key rotation can
retain the key named by an already queued row. The API has public verification
keys only; validation and acceptance receive the token in a POST body. The fresh
base schema contains only generation-pinned invitation and outbox contracts; no
earlier link format is accepted.

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

The extraction broker parses its network configuration before binding or
building provider clients. `BROKER_LISTEN` is a required socket address.
`BROKER_AZURE_API_VERSION` defaults to `2024-11-30`, and
`BROKER_AZURE_POLL_INTERVAL_MS` defaults to 2000 milliseconds and accepts
values from 2000 through 300000. Present malformed or out-of-range values stop
startup instead of silently falling back.

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

The control plane was extracted from a predecessor monolith into this repository; the
proposal that described that extraction, and the improvement programme that
turned the result into a release-managed platform, are both complete. Their
remaining gates live in `CONTROL-PLANE-ROADMAP.md` and their superseded
specifications remain available in Git history.
