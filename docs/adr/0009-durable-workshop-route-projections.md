# ADR 0009: Serialize workshop route projections with durable generations

- Status: accepted; core logical projection/application, recovery authority,
  and staged bounded-memory startup publication are implemented; a dormant
  release-generation filesystem foundation exists, but copy-on-write normal
  route publication and the active release overlay remain in progress
- Date: 2026-08-22
- Decision owners: control-plane maintainers

## Context

Gateway configuration is a complete workshop projection. Domain, module,
provisioning, periodic reconciliation, startup, recovery, and release workflows
can all change or rewrite it. A process-local mutex prevents overlap inside one
driver process, but it does not order replicas. Two valid operations can read
different database snapshots and later replace the same route file in reverse
order. Atomic rename prevents a torn file; it does not prevent a stale file.

The route file and gateway reload cannot reject a PostgreSQL fencing token.
Lease expiry therefore creates an unknown physical outcome and cannot safely
authorize automatic takeover.

## Decision

Maintain one durable logical route projection and one application lease per
workshop. The logical projection contains only stable desired state:

- database identity and platform hostname;
- Paperless route mode: `absent`, `read_write`, or `read_only`;
- Paperless hostname;
- sorted custom hostnames and their canonical flag.

It does not contain a physical Odoo container. The driver resolves the active
release slot while rendering, so a later domain or module reconciliation cannot
silently route traffic back to the legacy `odoo` upstream.

A short workshop transaction locks the projection row before reading source
state, canonicalizes the complete projection, and computes its SHA-256 digest.
If the digest changed, it stores the immutable projection at the next monotonic
generation. An identical projection reuses the current generation. The
transaction commits before HTTP, filesystem, container, or gateway effects.

Driver admission is bound to all of:

- workshop and projection generation/digest;
- durable control operation ID, attempt, lease owner, and unexpired lease;
- deployment-driver operation and idempotency digest;
- driver instance, execution token, route lease token, and fence token.

One workshop may have one physical route executor. Different workshops remain
independent at the logical projection and lease boundary. They cannot publish
different copy-on-write fleet generations concurrently: every change to the
single gateway selector must also hold one global selector authority. A lower
generation is superseded and performs no effect. A forged or unreserved
generation/digest is rejected. Exact successful replay returns stored evidence
without reacquiring the route lease.

The canonical lock order is control operation, shared release resource,
workshop route rows in UUID order, then deployment-driver operation. Release
route activation reserves every affected workshop in that order. Recovery is a
transient maintenance overlay on the same resource, not a second route writer.
Startup rebuilds the persisted logical projection through the same fenced
application boundary.

Successful finalization records the applied generation, logical digest,
rendered configuration digest, driver operation, and fence. Safe pre-effect
failure releases the lease without advancing applied state. Any ambiguous
rename, reload, timeout, expired lease, or unknown finalization quarantines the
workshop route. Quarantine is never cleared by ordinary workers or drivers; a
reviewed reconciliation command must prove the old executor is quiescent and
record authoritative filesystem and gateway observations.

## Migration and rollout

Existing workshops start `uninitialized`; migration cannot inspect host route
files. New workshops start at generation zero. Legacy successful generic driver
receipts are retained as audit evidence but are never accepted as fenced route
receipts. A uniquely attributable legacy in-progress route write seeds a
quarantined workshop. Ambiguous or unmappable legacy writers make migration
fail closed.

Rollout order is schema, fenced startup reconciler, initialization of every
existing workshop, then producers. Traffic stays fail closed for an
uninitialized, held-expired, or quarantined route.

Migration 0012 implements immutable generations, per-workshop application
leases, strict route evidence, quarantine, and least-privilege function grants.
Migration 0013 adds present/absent dispositions, durable startup and recovery
effect runs, global/workshop reservations, and stable maintenance ownership.
The shared producers and `route-project` driver path use that protocol. Fleet
release and startup acquire the global Odoo umbrella before their frozen
workshop route sets. Startup initializes only through a bounded source-equality
bridge and otherwise reads immutable projections. Recovery exits maintenance
to the latest desired projection and never restores route backup bytes.
Lifecycle deletion applies an absent tombstone before destructive effects. The
logical route-writer mutual-exclusion boundary is implemented. The physical
publication claim is not complete while normal and recovery writers can mutate
the selected generation in place.

Recovery maintenance is the first durable overlay implementation. Release
maintenance is not yet the same protocol: it still derives a maintenance route
from live route bytes, retains a `.recovery.bak` file, and restores those bytes
after reconnect. Its writes are covered by the release fleet and workshop route
reservations, so it does not introduce an unfenced concurrent writer, but it is
not an immutable, projection-derived overlay and must not be cited as evidence
that every overlay in this decision is complete.

## Staged, bounded-memory startup publication

The current startup implementation keyset-pages database reads, but then keeps
the tenant snapshot, verified-tenant map, immutable projection rows, rendered
route bytes, and expected runtime-name set in process memory. It also writes
each route directly into the live Nginx include directory before the single
reload. Changing `Vec::extend` to a page callback would reduce one allocation
while losing the single-snapshot contract and would not provide atomic
publication or crash recovery. It is therefore not an acceptable implementation
of bounded startup.

The implemented protocol makes a startup run a staged effect:

1. Admission freezes the route reservations and a durable runtime-verification
   snapshot. Each snapshot row is bound to the effect run, workshop, database
   identity, desired generation/digest/disposition, and unresolved-operation
   observation. No external I/O occurs in that transaction.
2. The driver reads at most 500 rows at a time. It reconciles and verifies the
   corresponding runtime, renders into an effect-run-specific staging
   directory, and records exact candidate evidence before advancing a durable
   cursor. Neither successful rows nor rendered bytes are retained in memory.
3. Pre-publication staging is recoverably disposable. Expiry before publication
   may release reservations only after proving that the staging directory was
   never selected. Once publication starts, expiry is an unknown outcome and
   quarantines the global and affected workshop route resources.
4. After every reservation has exact candidate evidence, a seal transition
   records the row count and deterministic projection-set digest. It rejects
   missing, duplicate, out-of-order, or non-current reservations.
5. Route files are published by an atomic selector change within the same
   filesystem. The stable Nginx configuration imports `current/*.conf`; the
   driver builds an immutable generation directory and atomically replaces the
   `current` symlink. The current normal and recovery writers still mutate that
   selected generation while holding only a per-workshop route lease. That is a
   compatibility bridge, not the final architecture: it can invalidate a
   published seal and cannot compose concurrent updates to different workshops.
6. The staged generation includes a driver-only Nginx generation endpoint.
   Successful reload is acknowledged only after an observation through the
   running gateway returns the exact effect-run ID and sealed digest. `nginx -t`,
   HUP exit status, the symlink target, or a filesystem digest alone is not an
   authoritative observation of the configuration serving traffic.
7. Finalization advances all applied heads only after that observation. A
   reconciler may finish an interrupted publication when the running generation
   is exactly the sealed candidate, or safely restore the prior selector when
   the old generation is still serving and the candidate was never activated.
   Any other combination remains fail closed and quarantined.

The renewal design must also change. Updating every workshop lease before and
after every row is quadratic in fleet size. A periodic whole-run heartbeat may
renew the frozen set in O(fleet) per interval, while a cheap exact assertion on
the current workshop and global fence brackets each filesystem or gateway
effect. Publication must stop immediately when either check fails.

Migration 0019 implements that independently safe prerequisite. One periodic
transaction authenticates the global lease, effect run, and complete frozen
workshop reservation set before assigning a single expiry to all of them. It
rolls back if any update count drifts. Constant-cost global and per-workshop
assertions do not extend leases and bracket the existing filesystem cleanup,
route-file mutation, and gateway reload calls. Heartbeat failure cancels the
in-flight Rust effect future and enters the existing outcome-unknown path.
Startup source discovery is available to the production driver only through a
fixed-search-path function bound to the exact unexpired run, tokens, global
fence, and `remove-uninitialized` reservation; initialization independently
reconstructs and compares that source before accepting it. This does not add a
selector, staging directory, durable cursor, seal, or publication transition.

The selected-generation filesystem substrate is also implemented independently
of the publication state machine. The stable Nginx configuration imports only
`current/*.conf`; the boot reset atomically selects a freshly emptied
`generations/boot-live` directory; and projection, startup, recovery, and
release route effects reject an obviously escaping or non-directory selector
before constructing route paths. This preserves today's boot-time fail-closed
behavior and gives publishers one atomic selector boundary. It is not a safe
mutation capability: the path-based resolver performs separate metadata and
canonicalization operations, returns a reusable `PathBuf`, and does not retain
the selected directory descriptor or device/inode binding across later I/O.
Normal and recovery mutation must move to descriptor-relative copy-on-write
publication before a sealed generation can become the long-lived selected
generation.

Fleet release publication uses the same boundary and now installs a distinct
protocol-v1, loopback-only loaded-generation identity. Nginx must return the
exact fleet run, driver action, original fence, route-set digest, and target
slot before the activation intent can record observation or activation time.
This is release-cutover evidence, not startup seal evidence, and does not clear
an interrupted fleet quarantine or replace the pending compensation protocol.

This protocol required a coordinated schema, filesystem-layout, gateway-config,
deployment-reset, runtime-observation, and reconciler rollout rather than a
Rust-only streaming refactor. That rollout is now integrated. Docker discovery
streams bounded pages of at most 500 exact runtime identities, and Quadlet uses
a bounded keyset page plus direct typed lookup for a selected resource. The
startup loop enforces a database-owned cursor and a fixed item budget, renders
and records each workshop before advancing, and retains neither a fleet-sized
tenant map nor rendered route bytes.

Migration 0024 introduces a child
`workshop_route_startup_runtime_reservations` table keyed by
`(effect_run_id, workshop_id)`. It stores only immutable admission facts and
bounded progress: database identity, desired projection identity, Paperless
expectation, unresolved-operation flag, runtime outcome, rendered digest, and
exact evidence. A one-to-one `workshop_route_startup_publications` row stores
the staging selector, prior selector, last completed workshop, candidate count,
set digest, and phase `staging | sealed | publication_started | observed |
quarantined`. Direct runtime-role DML is denied.

Fixed-search-path functions provide the only runtime transitions:

- admission inserts both runtime and route reservations in the existing lock
  order and returns no unbounded aggregate;
- a 1..500-row keyset reader authenticates the exact run, instance, execution,
  global lease, fence, and unexpired pre-publication phase;
- candidate recording compare-and-sets one reservation and advances the cursor;
- sealing proves every frozen row has exact evidence and freezes count/digest;
- publication start authenticates the sealed run immediately before the selector
  exchange;
- observation records only an exact running-gateway generation/digest;
- finalization advances applied heads and releases leases only from `observed`;
- interrupted-publication reconciliation accepts the exact old or candidate
  generation described above and quarantines every other observation.

Migration 0025 begins the release-overlay rollout without changing the active
release executor. A new, rolling-compatible protocol-v2 admission overload
freezes the complete fleet's exact applied immutable projections only when
desired and applied heads agree, every route is present and idle, and the fleet
snapshot's database/Paperless identity matches. The parent and per-workshop
snapshot tables are immutable, runtime roles have no table privileges, and an
exact live operation/global lease can read them only in keyset pages of at most
500. Validation failure rolls back the delegated release admission and global
lease atomically; protocol-v1 admission and replay remain unchanged. This is a
dormant data boundary: per-workshop release ownership, staged maintenance and
candidate generations, publication transitions, and interrupted overlay
reconciliation remain required before Rust may request protocol v2.

Migration 0026 adds the corresponding dormant database publication authority.
Admission freezes the exact upstream worker operation attempt, driver/global
lease, fleet snapshot, target slot, and one monotonically fenced
`release-overlay` lease per workshop. Function-only transitions record the
prior selector, keyset-read the immutable snapshot, compare-and-set exact
maintenance and candidate evidence, seal each projection set, begin selector
publication, and accept only the matching loaded-gateway identity. The
canonical lock order is enforced for reads as well as mutations. Expiry or an
unknown outcome moves the publication and all retained authorities into a
closed, phase-shaped quarantine; it never invents completion evidence.

Candidate observation advances only the exact frozen route applied heads and
stops at `awaiting_worker_finalize`. The global driver lease, per-workshop route
leases, driver operation, and upstream worker authority remain held. Migration
0026 deliberately supplies no whole-release success, rollback, or recovery
completion, and it rejects the legacy generic finish, renewal, and fleet-
reconciliation surfaces for protocol-v2 work.

A dormant Rust release-generation filesystem foundation complements these
database boundaries. It has deterministic, separate maintenance and candidate
generation names; reuses the audited descriptor-relative generation
primitives; stages bounded workshop-ordered routes; records an operation-bound
identity and candidate directory device/inode; and provides selector exchange,
prior restoration, exact observation, publication markers, and conservative
pre-publication disposal. No active release path calls either dormant boundary,
so migration 0026 does not activate protocol v2 or make the remaining flat
route writers safe.

## Copy-on-write prerequisite and activation order

The selector represents the complete fleet route set. Copying the same selected
generation into two per-workshop candidates and exchanging both selectors would
lose the first update when the second candidate wins. Per-workshop leases alone
therefore cannot authorize physical selector publication. The smallest safe
implementation serializes every selector-changing effect under the existing
global shared-runtime database authority and one cross-process route-root guard,
while retaining the per-workshop lease and fence as the semantic authority for
the route being changed. The lock order remains control operation, global
authority, workshop route rows in UUID order, then driver operation.

Each normal or recovery route effect must freeze a complete projection-derived
fleet snapshot, replacing only its authorized workshop projection, keyset-read
at most 500 rows per call, and render a new effect-specific generation. It must
not clone route bytes from `current`. Filesystem access remains
descriptor-relative; the database freezes the prior and candidate selector,
device, inode, count, digest, and loaded-gateway identity. Publication follows
`staging -> sealed -> publication_started -> observed`; only `observed` may
advance applied state and release selector/workshop authority. Before
`publication_started`, an exact unselected candidate is disposable. At or after
that transition, expiry or ambiguity quarantines authority and reconciliation
must prove or resume an exact selector plus running-worker identity.

This behavior cannot be enabled by a rolling migration alone. Old binaries know
only flat selected-generation mutation and could be admitted whenever the global
authority is briefly idle. A dormant schema and Rust implementation must land
first with existing signatures unchanged. Every live driver must then advertise
the copy-on-write protocol; an activation transaction must lock the global row
and workshop leases in canonical order, require no in-flight legacy writer or
quarantine, disable legacy mutation admission, and enable the new functions.

Implement and consolidate writer support in this order:

1. `route-project` publishes complete copy-on-write generations under global
   selector serialization;
2. recovery maintenance entry and exit use the same publisher and cease reading,
   backing up, or replacing selected route bytes;
3. the already staged startup publisher moves to the shared generation,
   identity, reconciliation, and retention implementation;
4. release maintenance and candidate publication activate protocol v2 only
   after the preceding writers can no longer mutate a selected generation.

These are implementation milestones, not independently enabled rollout
states. The runtime transition is one coordinated, irreversible activation
after all four writer families advertise the generation protocol and every
flat mutation admission is disabled. Otherwise a remaining recovery or
release v1 process could mutate a generation sealed by an already-enabled
normal publisher and invalidate its durable evidence.

Until that sequence and capability gate are complete, migrations 0025 and 0026
and the dormant release filesystem code are prerequisites only. The narrow
database state machine is complete through `awaiting_worker_finalize`; active
release protocol v2 and whole-release finalization must not be reported as
complete.

Startup and durable recovery now share one private typed projection parser and
renderer. It validates the six-field JCS digest, RFC UUID/database-reference
binding, hostname set, disposition, Paperless mode, and deterministic runtime
names before producing normal, absent, or maintenance bytes. Its streaming
evidence fold is length-framed and bounded. The legacy release path does not
consume this type yet and therefore still cannot be described as projection-
derived.

Running-generation observation (2026-08-22): the driver has
a closed `GatewayGenerationIdentity` contract, a renderer for the
generation-owned loopback-only Nginx endpoint, strict bounded JSON parsing, and
bounded Docker/Quadlet observation commands. The identity contains exactly the
startup effect-run UUID and sealed projection-set SHA-256 digest. Its Nginx
response is a literal in the parsed configuration, so changing candidate bytes
on disk does not change the observed identity until Nginx loads them. A real
Nginx test proves that distinction across a reload. Observation emits only the
two stable identity fields and fails closed on malformed, oversized, unknown,
or mismatched responses.

The staged publisher installs this endpoint in the immutable candidate, starts
the durable publication transition before selector exchange, reloads Nginx,
and observes the exact identity before recording `observed` and advancing any
applied head. Reconciliation can reload only a candidate already proven to be
selected and published, then repeats the same exact worker observation. A
selector, on-disk digest, successful syntax check, or signal-delivery status is
never accepted as running-worker evidence.

Acceptance coverage includes a 1,001-workshop 500/500/1 PostgreSQL run, bounded
batch rejection, stale route-fence and runtime-identity rejection, post-
admission fleet drift, safe pre-publication expiry, publication-started
quarantine/reclaim, candidate-forward completion, pristine-admission recovery,
and filesystem crash-boundary/order checks. The environment-dependent Nginx
test proves the observed identity belongs to the loaded worker rather than
merely to bytes changed on disk. The heartbeat regression gate continues to
require one whole-run renewal per interval rather than renewal per route.

Migration 0027 establishes only the dormant admission boundary for the future
universal route-set publisher. The singleton remains `flat_v1`, and all four
normal/recovery/startup/release readiness facts start false. Its projection
admission freezes the target desired projection and every other workshop's
applied projection under the global and ordered route locks, with a 500-route
ceiling and exact upstream-operation fencing. A protocol/global-row membership
guard serializes workshop insertion/deletion with admission and rejects it
while generation-mode global authority remains held or quarantined. It also reserves the closed
snake-case publication kinds and the Rust-compatible length-framed digest
domain. This is not an activation: recovery admission, record/seal/publish/
observe transitions, applied-head advancement, quarantine reconciliation, and
the coordinated legacy-writer cutover remain later work. No Rust path calls
the new functions. Admission replay is exact to the original execution and
resource tokens; fresh tokens conflict instead of transferring authority, and
exact identity after lease loss reports `authority_lost` pending that future
claim protocol.

Migration 0028 supplies the next dormant transition layer. It records each
snapshot row in UUID order, freezes the exact prior selector identity, seals
only an independently recomputed count/present-count/digest, records
`publication_started` before selector exchange, and accepts observation only
for the exact universal seven-field identity plus selector and device/inode.
Quarantine retains the fenced resources for later reconciliation. The path
stops at `observed`: it does not advance an applied head, finish the driver,
release authority, claim an interruption, admit recovery kinds, or activate
generation mode.

## Required acceptance evidence

- concurrent source changes allocate ordered immutable projections;
- delayed generation N cannot overwrite applied generation N+1;
- distinct driver replicas receive at most one workshop route token;
- exact replay, digest conflict, busy, expiry, and quarantine are covered on
  PostgreSQL 17;
- maintenance and release share the same route authority and lock order;
- restriction preserves custom hostnames and the active runtime upstream;
- no database transaction spans filesystem, gateway, container, or HTTP I/O;
- production roles cannot mutate route ledger tables directly;
- fresh and 0012-upgrade catalog tests prove grants and fail-closed migration.
- the running-generation endpoint returns the loaded effect-run/digest even if
  its source file changes, then returns the new identity only after reload.

## Consequences

This adds a small state machine and explicit reconciliation work, but makes
route application observable, ordered, and replica-safe. The local mutex
remains useful for reducing contention but is no longer correctness authority.
