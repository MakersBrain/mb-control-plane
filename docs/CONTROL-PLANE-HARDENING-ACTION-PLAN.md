# Control-plane architecture and hardening action plan

Status: active
Date: 2026-08-21
Scope: `mb-control-plane`

Current implementation progress:

- the reconstructed pre-change baseline, tenant-isolation threat model, and
  drift-checked public/internal route inventory are recorded in
  `docs/CONTROL-PLANE-HARDENING-BASELINE.md` and
  `docs/control-plane-route-security-inventory.tsv`; the inventory comes from
  the same registries that construct the Axum routers and includes every
  method, path, access policy, and handler symbol;
- every public HTTP method now declares `Public`, `VerifiedBearer`,
  `Authenticated`, `Workshop(WorkshopPermission)`, or
  `Platform(PlatformPermission)` access explicitly;
- each protected method has route-local middleware that authenticates and
  authorizes before its handler runs; workshop middleware inserts a validated
  `WorkshopScope` containing workshop, principal, role, and authority epoch;
- OpenAPI security is generated from the same policy instead of being inferred
  from URL prefixes;
- unit tests cover the permission matrices, rejection before handler side
  effects, validated scope insertion, invalid workshop IDs, path-family policy,
  and OpenAPI security consistency;
- a disposable-PostgreSQL handler-level gate now sends denied requests through
  every real workshop route registration, proves that no durable operation is
  admitted, and exercises an actual workshop-A/member-B read and mutation with
  database and command-state assertions; the policy-only fast matrix remains
  separate so its minimum-role assertions are not presented as handler/SQL
  coverage;
- all handlers declared with `Workshop(...)` access now consume the validated
  `WorkshopScope`; raw workshop path values are no longer used as their tenant
  authority, while resource-derived invitation and transfer routes retain
  explicit resource-scoped authorization;
- authenticated and bearer-bootstrap handlers consume the middleware-issued
  `Principal` or `VerifiedToken` instead of repeating token verification and
  identity lookup; invitation acceptance is explicitly a bearer-bootstrap
  route so a first-time invitee can create its local identity;
- platform handlers consume a middleware-issued `PlatformScope` instead of
  repeating operator and role-name queries; the middleware performs the single
  bootstrap-capable platform-role lookup, preserving the one-time initial
  technical-administrator grant before applying the declared capability;
- workshop mutations revalidate the exact membership role, permission, and
  authority epoch under a transaction-held membership lock before command
  admission or external side effects; ownership-transfer acceptance now
  authorizes the same locked row it mutates;
- platform mutations likewise re-query and share-lock the actor's active role
  grants inside the mutation transaction, then re-evaluate the route's captured
  `PlatformPermission` before command admission; role revocation therefore
  cannot race an already-authorized handler into admitting a stale command;
- a deliberately narrow CI source gate rejects string-literal mutations of
  workshop-owned child tables that lack a `workshop_id` predicate; this is a
  regression aid, not a substitute for the pending database isolation matrix;
- HTTP requests now accept only UUID-shaped inbound request IDs (generating one
  otherwise), return the ID on every response, and record it with response
  status and latency on the matched-route tracing span; valid inbound W3C trace
  context is attached to that span and malformed parents are rejected safely;
- durable operation metrics now expose admitted, completed, retried,
  dead-lettered, and expired-lease counts by closed operation kind alongside
  queue in-flight counts. An actual authenticated HTTP workshop admission
  persists its W3C context and a worker span consumes it in the PostgreSQL CI
  gate; direct workshop-provisioning and fleet-release admissions no longer
  bypass trace-context persistence;
- the document-extraction broker loads typed network/provider timing config at
  startup, and its extraction adapters share an outbound HTTP builder with a
  bounded connect timeout, redirects disabled, and explicit caller identity;
- durable workers load and validate their database URL, immutable release
  identity, queue-owned tenant domain, extraction limits/throttles, and privacy
  transport before telemetry or PostgreSQL; integration adapters construct
  clients through the shared outbound HTTP policy while retaining
  provider-specific authentication and total timeouts;
- the backup scheduler validates its database/driver endpoints, release
  identity, strict enable flag, bounded interval, credential, and optional
  socket before telemetry or PostgreSQL initialization;
- the migration executable validates its data mode and typed PostgreSQL URL
  once before telemetry; database URL validation is shared by API, worker,
  scheduler, and migration configuration rather than reimplemented per binary;
- the development fixture now requires its bearer secret and validates its
  optional issuer once at startup; handlers cannot silently authorize an empty
  token or rediscover configuration per request;
- bearer discovery/JWKS retrieval and mail delivery now share that external-API
  policy too, while keeping their narrower adapter-specific timeouts;
- internal service calls have a separate no-proxy client profile, preventing
  deployment-driver and mail-gateway bearer credentials from following ambient
  proxy configuration; mail-gateway provider and certificate clients retain
  the external profile;
- workshop-owned Odoo and Paperless adapters now clone process-scoped,
  no-proxy transport pools instead of building a Reqwest client for each
  durable-operation attempt; tenant bearer/API credentials, Odoo database
  filters, and adapter total timeouts remain request-local, with tests guarding
  both pool reuse and credential separation;
- Rauthy, Cloudflare, Scaleway TEM, and extraction-broker adapters now reuse
  process-scoped transports with credentials and total timeouts applied to the
  individual request; their external-versus-internal proxy policy and caller
  identities remain explicit;
- deployment and privacy workers validate their driver endpoints, Unix socket,
  bearer, and queue-specific timeout before leasing work, then reuse one
  process-owned transport; API carrier/recovery calls likewise reuse the
  `AppState` deployment-driver client;
- release finalization and terminal failure now share a durable lock order and
  are fenced to the current operation lease/attempt; final activation validates
  the immutable generation, canonical tenant snapshot, exact adoption set,
  completed activation intent, and manifest-bound runtime evidence, while
  unknown outcomes remain reconcilable instead of being marked failed;
- release fleet discovery is explicitly bounded to 500 tenants until durable
  chunking is implemented, and snapshot drift is rejected before driver-side
  Docker, PostgreSQL, or route effects;
- migration `0010_release_driver_lease` serializes the shared Odoo release
  resource across driver replicas with a database lease and monotonic fence.
  Admission is bound to the exact live release-worker operation attempt,
  release phases renew at effect boundaries, and worker finalization accepts
  only the succeeded driver receipt and matching fence. Expiry or an unknown
  outcome quarantines the resource instead of permitting an unsafe takeover;
  migration `0018_initial_release_reconciliation` now clears one deliberately
  narrow quarantine class: an empty-fleet initial preparation whose exact
  prepared slot and original fence are present and whose named Docker runtime
  passes a fresh read-only image/config/mount inspection. The observation has
  its own expiring database claim, strict receipt, stable tracing fields, and
  never replays an effect. Success finalization re-authenticates the exact
  current upstream lease and table-locks/rechecks the empty-fleet predicate
  through commit; an inconclusive observation retains quarantine.
  Fleet cutover reconciliation now has a durable database boundary in migration
  `0023_fleet_release_forward_reconciliation`: only a release binary which
  declared executor-observation protocol v1 before host effects can be claimed,
  and the expiring claim is bound to the original host instance, operation,
  fence, fleet run, immutable activation identity, and current upstream lease.
  Finalization is success-only and forward-only, requires a closed proof of
  prior-executor quiescence plus exact runtime, gateway, database-access, and
  old-runtime-retirement postconditions, and leaves every inconclusive result
  quarantined. The old admission signature remains rolling-deploy compatible
  while deliberately recording NULL protocol evidence, so its ambiguous
  outcomes remain non-reconcilable. Its cooperating-driver serialization
  prerequisite is present:
  normal release and reconciliation entry share one hardened cross-
  process advisory lock acquired before database admission and held through
  driver-receipt finalization. Acquisition is an async nonblocking retry loop,
  so cancellation drops the descriptor and no database transaction waits on
  host authority. The lock does not prove that Docker, systemd, or PostgreSQL
  work accepted before process death is terminal. Phase-boundary
  renewal is reinforced by a structured 20-second background heartbeat during
  release execution. Heartbeat failure cancels the in-flight effect future and
  enters the same outcome-unknown quarantine path; successful effect completion
  cancels the heartbeat before exact fenced finalization;
- migration `0022_release_gateway_generation_identity` makes a running Nginx
  observation a prerequisite for fleet activation-intent acknowledgement. The
  selected route generation embeds a strict protocol-v1 identity containing
  the fleet run, driver action, original fence, intended gateway digest, and
  target slot; the driver accepts only the exact bounded loopback response.
  Recovery route backups remain until that observation succeeds. Historical
  intents retain a NULL identity version and cannot be reconciled rather than
  receiving manufactured proof. The runtime observer and forward-completion
  path must use migration 0023's exact claim and evidence contract;
- migration `0025_release_route_projection_snapshot` adds a dormant,
  rolling-compatible protocol-v2 release admission. It freezes a complete
  fleet of exact applied immutable route projections under the existing lock
  order, exposes them only through an exact-lease keyset reader capped at 500,
  and rolls admission back atomically on projection or fleet drift. Runtime
  roles cannot access the snapshot tables directly. Startup and durable
  recovery also share a strict typed projection parser/renderer with
  deterministic maintenance output and length-framed streaming evidence. The
  active release executor deliberately remains on protocol v1;
- migration `0026_immutable_release_route_publication` adds the dormant,
  function-only publication authority for that exact snapshot. It acquires one
  fenced `release-overlay` lease per workshop, freezes the upstream operation
  attempt and driver/global authority, and records immutable maintenance and
  candidate evidence through seal, publication start, and exact running-worker
  observation. Candidate observation advances only the frozen applied route
  heads and stops at `awaiting_worker_finalize`, retaining the global, driver,
  worker, and per-route authorities. Phase-shaped quarantine covers only expiry
  or outcome-unknown states, while protocol-v2 calls through legacy generic
  finish, renewal, and fleet-reconciliation surfaces fail closed. A dormant
  Rust release-generation filesystem foundation provides deterministic names,
  descriptor-relative staging, operation-bound identity, device/inode evidence,
  conservative cleanup, and selector exchange/restoration primitives. No
  active release path calls this state machine; whole-release finalization,
  activation gating, and active protocol v2 remain incomplete;
- migration `0027_route_set_publication_admission` adds a second dormant,
  function-only boundary for projection-derived full-fleet generations. Its
  coordinated mode singleton starts in `flat_v1` with every writer capability
  false. Projection admission therefore remains unreachable until later
  migrations replace and guard normal, recovery, startup, and release flat
  writers and perform one atomic activation. The admission ledger freezes the
  target desired projection plus every non-target applied projection, proves
  exact fleet cardinality under ordered locks, fences workshop membership for
  the logical lifetime of non-idle global publication authority, and holds the
  global and target route fences through bounded reads and renewal. Record, seal, selector
  publication, observation, applied-head CAS, quarantine, interrupted claims,
  recovery-kind admission, and activation are intentionally not exposed by
  this bounded tranche; no Rust call site uses it;
- migration `0028_route_set_publication_transitions` extends that dormant
  authority through ordered record, prior-selector, seal, durable publication
  start, and exact seven-field loaded-worker observation evidence. Every tuple
  has exact replay and write-once enforcement; candidate records are bound to
  the frozen snapshot and preserve non-target applied bytes. Pre-start expiry
  and post-start outcome ambiguity quarantine the exact global, target-route,
  and driver authorities. Observation retains all authority and deliberately
  stops before applied-head CAS, final success, lease release, interrupted
  claim, or recovery-kind admission; those remain later migrations;
- migration `0029_route_set_publication_finalization` adds projection-only,
  atomic finalization after exact loaded-worker observation. It compares and
  swaps the complete frozen prior applied tuple and desired target tuple,
  advances only the target applied head, persists one database-constructed
  seven-field route receipt plus immutable route-set evidence, succeeds the
  driver operation, and releases both leases while retaining their fences in
  the same transaction. Completed calls and result reads replay the exact
  stored receipt. Activation, abort, recovery claims, interrupted
  reconciliation, and recovery-kind finalization remain deliberately absent;
- migration `0030_route_set_publication_recovery` adds dormant, function-only
  discovery and separately fenced claims for interrupted projection route-set
  publications. Only expired original authority can be quarantined and
  claimed. Pre-publication claims are explicitly `write_cleanup`; every claim
  after durable publication start is `observe_only` because a PostgreSQL fence
  cannot fence an earlier filesystem writer. Candidate, prior, unstarted, and
  inconclusive observations are immutable, replayable, and non-terminal in
  this conservative tranche: they never restore a selector, advance an applied
  head, release quarantined fleet membership, activate the protocol, or admit
  or finalize a recovery-kind publication. Terminal recovery remains a later
  reviewed migration;
- migration `0031_route_set_publication_terminal_recovery` adds a dormant,
  function-only reviewed terminalization step for immutable 0030 observations.
  Candidate evidence may advance only the target applied head by exact CAS;
  exact prior or unstarted evidence records a failed, non-applied driver result.
  Both release the quarantined route and global resource rows only in the same
  full-authority transaction. Inconclusive evidence remains quarantined and
  nonterminal. The protocol gate and all Rust call sites remain unchanged;
- migration `0032_route_set_flat_writer_guardrails` makes every retained normal,
  recovery-maintenance, startup, rolling-compatible release, quarantined-release
  reconciliation, interrupted startup/recovery-exit claim, and dormant
  immutable-release publication admission lock the route-set protocol singleton
  before any other admission lock. The public
  signatures and legacy refusal vocabulary remain stable in `flat_v1`, while
  `activating_v1` and `generation_v1` refuse without mutation. Renamed flat
  implementations are private to the schema owner. Readiness flags remain false
  and no activation API or active Rust dispatch is added;
- migration `0033_route_set_recovery_publications` adds dormant, effect-owned
  full-fleet publications for recovery maintenance entry and restoration. Entry
  publishes a projection-derived maintenance generation without changing the
  logical applied head; restore freezes the latest desired target and may
  advance only that target by exact applied-head CAS. Both retain the existing
  recovery effect and route fence, use the shared global generation authority,
  and return exact replayable route and route-set evidence. A restore requires
  a completed or candidate-recovered 0033 maintenance-entry publication; legacy
  flat maintenance effects are refused. A prior/unstarted restore attempt stays
  immutable, while a newer lifecycle attempt may create a new restore
  publication. Durable results are read by exact publication, effect, and
  control-operation identity before host preflight and again after host-guard
  acquisition. Protocol readiness remains false and no active dispatch or
  activation API is added; a later activation tranche must first define the
  worker mapping for maintenance-entry `not_applied`;
- migration `0034_route_set_startup_publications` adds a dormant fleet-scoped
  startup publisher to the universal route-set ledger without inventing a
  target workshop, control operation, or target fence. Admission freezes the
  desired route fleet and active shared-runtime evidence, refuses fleets above
  500 before mutating an effect, publication, or authority row, and permits a
  nullable applied baseline only for genuinely uninitialized startup routes.
  `BootLive` is accepted only by the startup-specific prior transition. Exact
  six-key loaded identity and the existing five-key startup receipt gate one
  atomic all-head finalization. Publication-specific reconciliation restores
  each pre-start lease state for exact prior or unstarted evidence, advances
  every frozen head only for an exact post-start candidate, and retains
  inconclusive evidence in quarantine. Protocol readiness and production call
  sites remain dormant. Shared retention-ledger integration remains a separate
  later tranche rather than being implied by this migration;
- migration `0035_route_set_generation_retention` adds that dormant shared
  retention boundary for candidate directories owned by the universal
  route-set ledger. It protects the newest two exact candidate observations
  and every selector still referenced by unresolved universal, startup, or
  release work. A single-publication claim takes a distinct, fenced global
  `route-set-retention` authority; expiry requires fence-incrementing takeover.
  PostgreSQL authorization commits before filesystem work and is necessary but
  insufficient: the driver must also hold the shared host guard, prove that
  `current` is not the target, and remove it descriptor-relatively. Deleted or
  already-absent evidence creates a durable tombstone. Current-selector and
  identity-mismatch observations release the global authority but remain
  retryable under a later fence. The migration neither collects legacy startup
  or release artifacts nor changes readiness or active dispatch;
- migration `0036_release_route_publication_finalization` closes the dormant
  protocol-v2 release route publication after exact candidate observation. It
  stores an immutable, replayable driver response and atomically releases the
  global and all frozen route authorities. The existing release worker remains
  the only writer of tenant/runtime/release/fleet-run activation state; recovery,
  release retention, readiness, and active dispatch remain later work;
- migration `0037_release_route_publication_recovery` adds a specialized,
  separately fenced recovery path for interrupted protocol-v2 release route
  publications. A newer live release-adoption attempt authenticates the claim;
  durable authorization precedes cleanup, restoration, or forward publication;
  exact terminal replay survives claim expiry; and mixed or inconclusive
  filesystem observations retain quarantine. The path remains dormant;
- migration `0038_release_generation_retention` closes release-overlay artifact
  retention without enabling dispatch. Immutable terminal subjects cover both
  normal/recovered completion and prior restoration, while cleanup/unstarted
  outcomes create no subject. One unified newest-two calculation protects
  applied universal and release candidates, and unresolved references across
  all publication families remain ineligible. Per-artifact fenced claims,
  immutable attempts, the shared host guard, exact intent/identity/device/inode
  validation, repeated current-selector exclusion, and one-child-per-renew
  descriptor-relative deletion form independent authorization layers. The
  strict Rust adapter/coordinator is private and tracing excludes capabilities,
  selectors, digests, and filesystem identities;
- dormant retention discovery is now implemented as a bounded, injected
  scheduler over the universal and release ledgers. Each keyset page is at most
  100 entries, each epoch is capped, lanes alternate, and filesystem execution
  remains strictly serial because both coordinators share the global authority
  and host guard. Cursors advance only after a handled outcome, so supervisor
  capacity pressure and retryable failures cannot skip work. Backoff is capped,
  jittered, stop-aware, and logged only with closed classifications and delay
  buckets. The release compound cursor uses the same explicit candidate-before-
  maintenance ordinal in Rust and SQL, independent of collation;
- startup recovery now has a typed, strictly validated discovery adapter. It
  rejects nil or non-monotonic cursors, oversized pages, unknown phase/claim
  combinations, malformed snapshot counts, and missing or malformed sealed
  digests before any coordinator dispatch;
- migration `0039_interrupted_release_route_snapshot_reader` closes the first
  interrupted-release input gap without authorizing an effect. An active exact
  recovery claim may read the immutable 0025 snapshot only for quarantined,
  forward-only `candidate_staging`, in UUID-keyset pages of at most 500. The
  function rechecks snapshot/header cardinality, publication ownership, and the
  claim's frozen route heads on every page; explicit completion and refusal
  rows make claim loss distinguishable from EOF. The Rust adapter shares the
  normal publication snapshot validator and rejects nil/non-monotonic cursors,
  mixed outcomes, malformed sentinels, projection/slot drift, and oversized
  pages. It remains private and uncalled. Interrupted release recovery still
  lacks immutable runtime observation/completion receipts and independently
  privileged terminal review needed for an evidence-safe coordinator;
- migration `0040_interrupted_release_runtime_expectation` adds the dormant
  claim-authenticated expected-input side of runtime reconciliation. It binds
  the release manifest, operation/fleet/fence/slot identity, prepared tenants,
  tenant snapshot, and gateway intent, while deliberately excluding live or
  locally derived runtime claims. Rust validates the closed payload and traces
  only safe identifiers/outcomes. The same migration blocks all new
  `unstarted` decisions and BootLive/null-identity prior decisions, and checks
  historical unsafe rows again at finish time. Runtime observation, immutable
  completion receipts, independent review, and dispatch remain future atomic
  work;
- migration `0041_interrupted_release_runtime_receipt_review` completes the
  dormant evidence and authority split for candidate recovery. The driver
  submits an exact allowlisted live observation, while PostgreSQL validates it
  against 0040 state and builds the canonical completion response. Candidate
  authorization and resolution consume that immutable receipt rather than a
  caller response. A release-worker-only review binds its digest to the exact
  route-resolution digest, and the driver finalizer consumes only an accepted
  stored review, never a caller decision digest. Immutable tables deny direct
  runtime-role access, compatibility bypasses are private or fail closed,
  typed adapters reject unknown outcomes/shapes, and tracing excludes tokens,
  response bodies, digests, selectors, and runtime details. Replay, conflict,
  claim loss, missing review, ACL separation, historical bypass rejection, and
  the normal-versus-recovery terminal race are covered on PostgreSQL 17. The
  modules remain private and uncalled, so no recovery dispatch or external
  effect is enabled;
- release-runtime observation is now a single private, observation-only Rust
  boundary shared by the active protocol-v1 reconciliation and the dormant
  0041 receipt path. Its opaque verified value can be constructed only after
  exact executor quiescence, candidate/retained runtime and policy inspection,
  verified recovery-backed tenant-set parity, exclusive credentialed database
  access, tenant identity/readiness checks, route digest parity, and loaded
  rolling-gateway identity. The receipt adapter no longer accepts a
  field-buildable collection of positive booleans. All filesystem inputs are
  now captured by one private read-only port in a single `spawn_blocking`
  snapshot: runtime and exact workshop-keyed bridge credentials, selected
  generation validation, and at most 500 route files. Secret wrappers have no
  debug or serialization surface, key-set parity is fail-closed, and async
  readiness checks use preloaded tokens. The observer contains no mutation,
  dispatch, nested-runtime, claim, timeout, or persistence policy. Protocol-v2 loaded
  candidate proof remains after publication in route resolution and is bound by
  independent review. Recovery/review adapters now parse database outcomes
  before tracing, expose only closed vocabularies (or `contract_drift`), and
  omit workshop IDs and evidence details. Dormant route-set recovery database
  outcomes now use the same parse-before-trace rule, and the release recovery
  adapter accepts migration 0040's authoritative `unsupported_resolution`
  literal while rejecting the stale `unsafe_resolution` spelling;
- the driver now owns one bounded task-supervisor actor for dormant route-set,
  recovery, startup, and universal/release-retention effects. Admission is
  linearized with drain, completed tasks are continuously reaped, and only an
  already-owned task capability may add safety cleanup after drain starts.
  Singleton long-lived services are registered by task kind, consume no effect
  permits, have separate queued/active metrics, and receive a synchronous stop
  signal when drain begins. They are reaped and included in the same terminal
  failure accounting as effect roots. Any service exit before drain, including
  `Ok`, is converted to a closed failure and starts drain so readiness cannot
  remain true with a silently dead scheduler;
  Readiness closes from that same admission state before Axum stops accepting;
  both TCP and systemd-socket processes then finish HTTP requests, drain roots
  and descendants, and keep pools/runtime clients alive until drain completes.
  Concurrent drain callers share one terminal result, task panic/cancellation
  makes process shutdown fail, and no internal timeout abandons safety work;
- the dormant route-set coordinator keeps one absolute lease-renewal
  schedule across publication and finalization, resolves terminal races by an
  exact durable result read, and transfers cancellation cleanup to an explicitly
  owned supervisor that retains the host guard until quarantine or a terminal
  receipt is confirmed. Cleanup confirmation uses capped jittered backoff and
  sparse closed-class events instead of unbounded high-rate error logging. The
  protocol registry intentionally still has no production dispatch call site;
- the generation-retention scheduler has only an explicit dormant supervisor
  registration seam. Neither driver binary calls it, so this tranche starts no
  polling, changes no readiness rule, and activates no generation-v1 protocol;
- migrations `0019_startup_route_heartbeat_fences` and
  `0024_staged_startup_route_publication` replace startup's per-route
  whole-fleet renewal with one atomic O(fleet) heartbeat per interval. Exact
  non-renewing global/workshop assertions bracket filesystem and gateway
  effects, heartbeat loss cancels the in-flight effect, and the production
  driver reads an uninitialized projection source only through a
  fixed-search-path function bound to the exact startup run and reservation.
  Startup now admits one frozen database snapshot, reads and verifies it in
  keyset pages of at most 500 workshops, streams exact route evidence into an
  immutable generation, seals it in both PostgreSQL and the filesystem, and
  publishes it with one atomic selector exchange. Nginx acknowledges success
  only through the exact loopback generation identity loaded by its running
  worker. Interrupted runs reconcile under the shared Odoo host guard before
  new admission: exact pre-publication states restore the prior generation,
  an exact selected candidate completes forward, and every ambiguous state
  remains quarantined and keeps readiness false. Nginx imports only
  `current/*.conf`, boot atomically selects a fresh fail-closed generation, and
  every route writer resolves the same validated local selector before file
  I/O;
- the lease migration reconstructs normal historical target keys, quarantines
  an unknown in-progress legacy release, and refuses an unfenced historical
  success. Such a success must be reconciled before deployment because neither
  a trustworthy fence nor current driver receipt can be manufactured;
- privacy access and portability exports now bind the request, leased operation,
  and target user; fleet discovery is bounded to 50 workshops, each membership
  and processor configuration is re-read through a transaction-only tenant
  capability, and all database snapshots commit before processor or filesystem
  effects. Export-task evidence and request completion share a lease-fenced
  transaction, while API consumption commits its one-time state change before
  artifact I/O;
- migration `0017_privacy_export_cleanup_lease` serializes destructive export-
  artifact cleanup across privacy-worker replicas with a two-minute database
  lease and monotonic fence. Cleanup renews before database and per-file effect
  boundaries; the idempotent file deletion is acknowledged only while the exact
  owner, token, fence, and unexpired lease remain current. A crash after file
  deletion is therefore recovered by a later replica without allowing a stale
  executor to publish completion, and lease ownership is never logged;
- migration `0020_privacy_retention_batches` removes direct fleet-retention
  writes from the privacy worker. Each fixed-size batch authenticates the exact
  operation attempt, lease owner, payload binding, and unexpired lease inside a
  fixed-search-path database capability; legal holds are re-evaluated in the
  same transaction as each mutation. The first batch freezes one cutoff and
  monotonic high-water mark per dataset behind a table-lock snapshot barrier,
  so backdated concurrent inserts are deterministically deferred to the next
  run. Durable phase cursors and bounded counters make retry idempotent; held
  rows are intentionally reconsidered only by a later run after hold release;
- the container Engine transport, identity-administration client, and Odoo
  readiness transport are pooled using internal no-proxy profiles; startup and
  release readiness retries attach tenant bridge credentials and database
  filters per request instead of constructing clients inside their loops;
- the API now parses its extraction-broker URL and credential at startup and
  reuses one internal-service client for product lookups instead of reading
  configuration and constructing a client inside the request path;
- CI now rejects direct environment reads outside reviewed typed-config,
  secret-resolution, telemetry, system-activation, and test boundaries, and
  rejects production Reqwest construction outside the reviewed outbound HTTP
  policy boundary;
- shipping, webshop, domain, email-domain, and SMTP views now consume generated
  OpenAPI response models; provider-owned JSON is projected through explicit
  sanitized view-model conversions instead of being re-declared as trusted API
  structure;
- durable trace serialization and worker-parent attachment share one validated
  W3C seam; fast tests prove trace-ID continuity and outbound propagation with
  credential-safe logs, while disposable-PostgreSQL coverage verifies the
  persisted operation fields when that test environment is available;
- internal API failures are logged once as a bounded chain of stable error
  classes rather than raw error messages; captured-log tests cover bearer,
  email, payload, and mounted-secret-path canaries;
- durable workers, deployment drivers, the mail gateway, and the extraction
  broker use the same privacy-safe classifier and closed field vocabularies;
  captured-log tests additionally cover hostnames, trace/lease metadata,
  provider bodies, and startup resources, while a source gate rejects unsafe
  structured and fallback logging patterns;
- all 12 internal routes now live in a separate explicit registry with six
  credential domains; 11 header/path-scoped routes reject unauthenticated calls
  before their handlers, while the carrier-secret resolver is the sole explicit
  body-scoped exception;
- the generated workshop route matrix covers all 38 workshop method policies,
  including missing identity, non-membership, another workshop's authority,
  insufficient role, and the minimum permitted role; live PostgreSQL coverage
  for the complete cross-tenant SQL matrix and database-enforced isolation
  remains pending; ADR 0008 records the staged hybrid database design, the API
  now has distinct tenant and platform/internal execution pools. Forced RLS is
  enforced on `ownership_transfers` and on the scoped recovery-component
  ledger; migration 0016 removes its unused platform-API grant and admits only
  lifecycle and driver transactions carrying the exact workshop capability.

## 1. Outcome

Strengthen tenant isolation, configuration ownership, API-contract reuse, HTTP
integration policy, and production observability without replacing the
control-plane architecture or introducing abstractions that have no concrete
use.

The work is complete when:

- every workshop route is authenticated and authorized by its route
  declaration before its handler runs;
- cross-workshop access is rejected by an automated route-coverage gate;
- every executable parses all of its required and optional configuration before
  it starts serving requests or leasing work;
- generated API types are the only frontend definitions of generated response
  models;
- outbound HTTP clients are reused and have explicit, documented policies;
- HTTP requests and durable operations can be followed through structured logs
  and OpenTelemetry traces without exposing credentials or personal data;
- the normal formatting, lint, unit, integration, generated-contract, and
  topology-isolation checks pass.

This plan refines the findings in `review-note.md`. It does not treat the number
of traits, modules, or layers as a quality metric.

## 2. Engineering principles

### 2.1 Architecture

Keep the existing feature-oriented architecture. Organize code around control
plane capabilities such as workshops, recovery, releases, domains, and privacy,
not around generic `controllers`, `services`, and `repositories` directories.

Use these boundaries:

```text
HTTP / queue entrypoint
        |
        v
application operation  -----> domain types and policy
        |
        v
concrete persistence and integration adapters
        |
        v
PostgreSQL / Odoo / Paperless / Rauthy / deployment driver
```

- Handlers parse transport input, invoke one application operation, and map its
  result. They do not own authorization policy or integration orchestration.
- Domain types contain validation and policy that can run without Axum, SQLx,
  or Reqwest.
- SQLx queries stay close to the feature that owns them. Do not add a generic
  repository layer over SQLx.
- Define a trait only at an actual replaceable I/O boundary or a useful test
  seam. Prefer concrete types until a second implementation exists.
- Prefer small newtypes and enums over unvalidated strings and Boolean policy
  flags.
- Keep `AppState` explicit. Do not introduce a service locator or global mutable
  application state.

Material boundary changes require an ADR under `docs/adr/`. In particular, the
database-level tenant-isolation decision in phase 2 requires an ADR.

### 2.2 Errors

- Use typed `thiserror` errors for domain, application, and integration failure
  classes that callers must handle.
- Use `anyhow` at executable startup and for genuinely unexpected internal
  context, not as a public application contract.
- Map errors to `ApiError` once at the HTTP boundary. Responses expose stable,
  safe error codes and never expose an internal error chain.
- Log an error once at the boundary that decides its outcome. Lower layers add
  context and return it; they do not repeatedly log the same failure.
- Preserve the existing distinction between retryable, terminal, and
  unknown-outcome integration failures.

### 2.3 Change strategy

Make vertical, reviewable changes. A phase may touch many handlers, but each
commit must leave the executable and generated contracts consistent. Do not
combine tenant-authorization changes with unrelated cleanup.

## 3. Phase 0 — baseline and threat model

Before changing behavior:

1. Record the current results of `make check` and `make test`.
2. Generate an inventory from `api/routes.rs` containing method, path, current
   security classification, workshop scope, required permission, and handler.
3. Classify internal routes separately; do not apply human workshop membership
   rules to machine-authenticated bridge routes.
4. Write a short tenant-isolation threat model covering:
   - a missing membership check;
   - checking workshop A and querying workshop B;
   - an unscoped list or update query;
   - a child resource ID belonging to another workshop;
   - stale role or authority-epoch use;
   - worker and internal API access outside the human API path.
5. Add two synthetic workshop fixtures, users with different roles, and
   workshop-owned child resources for authorization tests.

Acceptance criteria:

- every public and internal route is in the inventory;
- the baseline test results and any pre-existing failures are recorded;
- the threat model defines the guarantees expected from HTTP authorization and
  from database scoping separately.

## 4. Phase 1 — structural HTTP authorization

### 4.1 Replace Boolean route security with policy

Replace `PublicRouteSpec.secured: bool` with an explicit access policy. The
exact names may change, but it must represent at least:

```rust
enum RouteAccess {
    Public,
    Authenticated,
    Workshop(WorkshopPermission),
    Platform(PlatformPermission),
}
```

Use capability-oriented permissions such as `ViewWorkshop`, `ManageMembers`,
`ManageModules`, and `ManageDatabase`; do not encode policy as
`require_access(..., true)` or compare role strings in handlers.

The route declaration remains the single source used to construct the Axum
router and OpenAPI security metadata. Its access policy must also install the
corresponding authorization middleware. A workshop handler must not run until
the middleware has:

1. authenticated the principal;
2. parsed the workshop path parameter;
3. loaded the active membership, role, and authority epoch;
4. checked the declared permission;
5. inserted a validated `WorkshopScope` into request extensions.

`WorkshopScope` should contain only validated authority context:

```rust
struct WorkshopScope {
    workshop_id: WorkshopId,
    principal_id: UserId,
    role: WorkshopRole,
    authority_epoch: AuthorityEpoch,
}
```

Handlers consume the scope and stop accepting a separate workshop UUID and raw
authorization headers. Child-resource queries must constrain both the child ID
and `scope.workshop_id`.

This makes authorization mandatory at the router boundary. The extractor alone
must not be described as a complete compile-time tenant-isolation guarantee.

### 4.2 Consolidate policy

Move role-to-permission decisions into one domain policy module. Replace the
local manager/database-owner helpers only after their route policies and
module-enabled preconditions have been distinguished:

- authorization answers whether the principal may attempt an action;
- feature-state checks answer whether the action is currently available.

Do not hide module-enabled, lifecycle-state, ETag, or idempotency checks inside
the authorization extractor.

### 4.3 Authorization gates

Generate or parameterize tests from the route inventory. For every workshop
route, verify:

- no token is rejected;
- a non-member is rejected;
- a member of another workshop is rejected;
- an insufficient role is rejected;
- the minimum allowed role succeeds;
- a child resource from another workshop is not found;
- rejected mutations produce no database or external side effect.

Add a CI assertion that every `/v1/workshops/{id}` route declares
`RouteAccess::Workshop`. Add explicit exceptions only for routes whose threat
model justifies them.

Acceptance criteria:

- handlers no longer call the duplicated `require_*` membership wrappers;
- all workshop route policies are visible in `api/routes.rs`;
- the cross-tenant route matrix passes;
- OpenAPI security output remains correct and the generated client is fresh.

## 5. Phase 2 — database tenant-isolation defense

HTTP authorization and SQL scoping solve different problems. Decide and record
the database defense in an ADR after a small feasibility spike.

Evaluate these options:

1. PostgreSQL row-level security with transaction-local principal/workshop
   context and forced RLS for runtime roles.
2. Narrow, workshop-scoped persistence functions that accept `WorkshopId` and
   make unscoped feature queries difficult to write.
3. A combination: RLS for the highest-risk workshop-owned tables and scoped
   query APIs elsewhere.

The spike must test connection-pool reuse, transaction boundaries, background
workers, internal machine identities, migrations, and the runtime-role matrix.
Never store session tenant context on a pooled connection outside a transaction.

Feasibility decision (2026-08-22): ADR 0008 selects a staged hybrid. Explicit
workshop-scoped persistence remains mandatory now; forced RLS is gated on
separate tenant/platform execution pools and transaction-local workshop context,
plus replacement or explicit classification of fleet-wide worker scans. The
ignored `tests/tenant_isolation.rs` PostgreSQL spike impersonates every deployed
runtime role, characterizes the still-table-ACL-only workshop/operation surface,
and names the partially protected catalog surface. It remains characterization
evidence rather than the complete isolation acceptance gate.

First-wave inventory progress (2026-08-22):
`docs/tenant-isolation-first-wave.json` now enumerates the exact ADR candidate
tables, direct or parent-derived tenant keys, API/worker/scheduler/driver touch
paths, triggers, foreign keys, security-definer functions, current runtime-role
grants, and the next workflow review for each table. Fast tests keep that
inventory aligned with every deployed runtime role, migration grant, database
object, and ADR candidate.

First enforced candidate progress (2026-08-22): `control-api` now owns distinct
`Store` and `TenantStore` pools backed by `control_api` and
`control_tenant_api`. `WorkshopTransaction` installs validated workshop context
with transaction-local `set_config`; direct first-wave workshop reads and all
revalidated workshop mutations use it. Ownership-transfer acceptance performs
platform discovery before a tenant-scoped locked re-read. Migration 0005 adds a
fail-closed context helper plus enabled and forced RLS policies for
`ownership_transfers`; the manifest records its policies and migrated status.
The disposable-PostgreSQL CI gate now exercises the production tenant pool,
connection reuse, malformed and missing context, catalog policy flags, role
non-membership, and cross-tenant CRUD denial for that protected table. All
other candidates remain pending, along with worker execution-scope migration
beyond the membership queue and extension of the direct-SQL/application matrix
to those future policies.

First worker execution-scope progress (2026-08-22): all 16 durable operation
kinds now resolve through a closed lease-time contract: 13 require a non-nil
workshop, while release adoption and the two privacy workflows require fleet
scope. The resolver rejects unknown kinds, queue mismatches, and invalid
workshop nullness before dispatch; rejected contracts cannot invoke tenant
handlers or their terminal cleanup callbacks. Fleet lease, heartbeat, renewal,
and completion remain on `Store`. The `membership-provisioning` queue is the
first fully migrated tenant execution slice: it receives a transaction-only
`TenantStore` capability over the queue-specific worker pool, reads membership
and service snapshots in a short `WorkshopTransaction`, commits before any
Rauthy/Odoo/Paperless call, and records results in fresh workshop transactions.
Static and disposable-PostgreSQL tests cover the seam through the real
`control_membership_worker` login. This is execution-scope proof, not RLS on
`memberships`; the remaining queues and table-policy reviews are still pending.

Durable-operation lease correction (2026-08-22): generic worker handlers and
their terminal compensation now execute inside one structured heartbeat scope.
A definitive lease loss or renewal failure drops the in-flight handler before
terminal callbacks or finalization can run, while handler completion cancels
the heartbeat without leaving a detached task. Renewal authenticates the exact
owner and attempt and additionally requires the existing lease to remain
unexpired, so a paused worker cannot resurrect authority; checkpoint and
terminal writes enforce the same tuple and expiry. Dropping a future stops
further local dispatch but does not retract an external request already
accepted by a provider, so each adapter's idempotency and unknown-outcome
reconciliation contract remains mandatory. Lease-loss tracing
uses only the operation identity, closed kind, attempt, and stable outcome
class. Unit tests cover both cancellation directions and heartbeat failure; a
live PostgreSQL test proves an expired lease timestamp is unchanged by renewal.

Email and lifecycle ownership progress (2026-08-22): `email.delivery` now
receives the validated workshop and transaction-only `TenantStore`, resolves an
outbox only when it belongs to that workshop, and retains the workshop predicate
on claim, retry, dead-letter, reconciliation, and success transitions. Ownership
resolution occurs before invitation signing or mail-gateway I/O. Migration 0006
backfills and requires `outbox.workshop_id`, closes the two allowed outbox
metadata shapes, binds invitation outbox workshop and recipient to the
authoritative invitation through a composite foreign key, and prevents a
webshop email domain from naming another workshop's test outbox. Lifecycle work
now validates every action-specific database and recovery identifier in a
`WorkshopTransaction` before progress or deployment-driver I/O; restore source
backups, safety backups, duplicate source/target pairs, deletion records, and
erasure replay selection are explicitly related to the leased workshop.
Terminal compensation retains the same workshop/operation predicates. Live
PostgreSQL tests prove forged email and lifecycle identifiers leave the other
workshop unchanged.

Lifecycle capability and relational-ownership progress (2026-08-22): lifecycle
commands are decoded once into a closed Rust enum whose variants carry the
complete action-specific resource set. After the fleet lease, the lifecycle
module receives only `TenantStore`; validation, atomic preparation, progress,
post-driver finalization, recovery-component writes, erasure replay checkpoints,
and terminal compensation all use short `WorkshopTransaction`s. Deployment-
driver calls occur only after the preceding transaction commits. A dedicated
`lifecycle.execute` span records the operation and closed action class without
payload or credential fields. The static worker gate scans the whole production
module and rejects any reintroduced `Store`/pool access. Migration 0007 adds
direct workshop keys to recovery components and erasure replays, binds lifecycle
children to their parents with composite foreign keys, repairs the lifecycle
worker's service-instance update grant, and removes its unused recovery-
rehearsal grant. Live tests prove forged ownership causes no driver request and
that a failed prepare compare-and-set rolls back database and progress changes
together. This completes the lifecycle queue's post-lease Rust capability
split; RLS remains pending because scheduler, release, privacy, and driver-ledger
workflows still require bounded fleet designs.

Webshop-domain capability progress (2026-08-22): migration 0011 replaces the
periodic fleet scan/enqueue loop with one bounded, concurrency-safe
`SECURITY DEFINER` claim. Selection, operation insertion, and exact
`(operation_id, workshop_id)` binding commit atomically, and the production API
cannot execute the claim. After lease validation, the domain feature receives
only `TenantStore`; it assembles route projections under `REPEATABLE READ`,
commits before Cloudflare, driver, or Odoo calls, and uses fresh transactions
fenced by operation ID, attempt, owner, expiry, workshop, and domain. The driver
rechecks the same upstream lease immediately before effects. Ambiguous create
sends remain `awaiting_reconciliation`; ambiguous delete sends leave a durable
dispatch claim and yield to the next bounded provider-observation cycle. Spans
expose only stable phase/outcome classes. This is a Rust capability boundary plus bounded claim,
not database-enforced tenant isolation: the reconciliation login still has
fleet table grants and the table has no forced RLS. Before this workflow is
ready, retain the route-authority boundary. Migrations 0012 and 0013 now add
immutable monotonic workshop projections, `present`/`absent` dispositions,
desired/applied heads, cross-replica application leases, durable fleet startup
and recovery-maintenance effect runs, strict receipts, and quarantine. The
shared producer materializes the complete canonical projection and the
driver's dedicated `route-project` action rejects altered, unreserved,
superseded, or disposition-mismatched payloads before effects. Restriction
preserves custom hostnames and resolves the active Odoo slot. Deletion commits
and applies an absent tombstone before destructive lifecycle I/O. Fleet release
and startup both acquire the global Odoo umbrella before the frozen workshop
route set; the driver renews exact leases around filesystem and gateway effects.
Startup rebuilds only immutable projections and readiness remains false until
that rebuild is durably acknowledged. Restore uses a stable maintenance effect
run and exits to the latest desired projection, never backup route bytes.
Migrations 0014 and 0015 complete the next reconciliation boundary. Ambiguous
provider deletion now uses a durable `(domain, provider reference)` intent,
authenticates every transition against the exact current operation lease,
permits at most four delete dispatches and eight observations, and finalizes
only after an authoritative provider-absence observation is durably recorded.
Periodic custom-domain, email-domain, and tenant admission now use atomic
security-definer claims with per-workflow cyclic cursors; each worker tick is
bounded to eight pages of 500 candidates, and startup tenant discovery uses a
500-row keyset scan under one repeatable-read snapshot. The accepted route
protocol and its rollout invariants are recorded in
[`ADR 0009`](adr/0009-durable-workshop-route-projections.md).

Periodic fleet-admission progress (2026-08-22): migration 0015 moves webshop
email-domain and general tenant drift admission behind fixed-search-path,
function-only database capabilities and adds a durable cyclic cursor to all
three periodic reconciliation workflows. Each function locks its private
cursor, selects at most 500 eligible rows with `FOR UPDATE SKIP LOCKED`, and
atomically creates tenant-bound operations; direct cursor access is denied to
runtime roles. A worker tick always advances eight pages because a page made
entirely of same-window idempotency conflicts does not prove exhaustion. The
hard capacity is therefore 4,000 considered rows per tick: every five minutes
for custom-hostname and email-domain work, and every six hours for general
tenant drift. Fleets above that bound advance fairly on later ticks rather than
starving the same UUID suffix. Driver startup tenant discovery is separately
keyset-paged in 500-row batches under one read-only repeatable-read snapshot;
the current implementation still retains the resulting tenant vector for the
subsequent two reconciliation passes, so its peak memory remains proportional
to fleet size.

Startup publication feasibility decision (2026-08-22): a local streaming
refactor is rejected because it would discard the single-snapshot guarantee
while routes are still written directly into the live Nginx include directory.
The bounded implementation is a staged effect protocol: admission durably
freezes runtime-verification and immutable-route rows; the driver verifies,
renders, and records candidates in pages of at most 500; an atomic `current`
selector publishes a sealed immutable generation; and the running gateway must
report the exact effect-run ID and sealed digest before applied heads advance.
Pre-publication staging is disposable, but publication-started expiry is an
unknown outcome and quarantines authority. The renewal path must use a periodic
whole-run heartbeat plus exact per-effect fence assertions, replacing the
current whole-fleet renewal before and after every route. This needs coordinated
schema, route-volume layout, Nginx generation observation, deployment reset,
and interrupted-publication reconciliation changes; the migration sketch and
invariants are maintained in [`ADR 0009`](adr/0009-durable-workshop-route-projections.md).

Running-generation observation prerequisite (2026-08-22): the deployment
driver now defines the exact effect-run/sealed-digest response, renders it as a
literal loopback-only Nginx endpoint, retrieves it with bounded Docker or
Quadlet commands, parses a closed bounded payload, and rejects every mismatch.
A real Nginx test proves that changing the endpoint source on disk is invisible
until reload. The helper remains intentionally unused by the flat publisher;
it becomes authoritative only when the staged selector embeds it in the
selected immutable generation and the durable publication transition consumes
the observation.

Selected-generation layout prerequisite (2026-08-22): the shared route volume
now has a single `current -> generations/<name>` boundary. Docker boot replaces
that selector atomically with an empty `boot-live` generation before Nginx
starts, retaining the previous fail-closed startup behavior. Projection,
startup, recovery, and release paths reject selector escape or a non-directory
target. The normal and recovery writers still resolve that selector through
separate path-based metadata/canonicalization calls and then mutate the returned
path. They do not retain a descriptor or device/inode binding across I/O. This
TOCTOU-prone flat mutation can also alter a generation after another protocol
sealed and selected it. It is a compatibility bridge, not an immutable
publication boundary.

Copy-on-write route prerequisite (2026-08-22): the selector names the complete
fleet route set, so two workshops cannot independently clone one prior and
exchange their candidates without losing one update. Preserve per-workshop
projection leases and fences, but serialize every selector-changing effect
under the global `runtime/shared-odoo` database authority and one cross-process
route-root guard. Each effect freezes and keyset-reads at most 500 canonical
projection rows, replaces only its authorized workshop in that frozen set,
renders a new descriptor-relative generation, and records exact prior and
candidate selector/device/inode plus loaded-gateway identity. No copy-on-write
publisher may derive its baseline from live route bytes.

The durable transition is `staging -> sealed -> publication_started ->
observed`. Exact pre-start candidates may be disposed; after publication start,
errors quarantine the global selector and affected workshop authority until a
reconciler proves or resumes the exact candidate and running-worker identity.
Retention is database-authorized and exact: never delete `current`, an
unresolved prior/candidate, `boot-live`, or the last two observed generations.
With 500 routes capped at 64 KiB, current plus two retained generations and one
staging generation has a bounded worst-case route-byte footprint of about
128 MiB before filesystem metadata.

Protocol activation must be explicit. Land schema/functions and Rust support
dormant with legacy signatures unchanged; require every live driver to
advertise copy-on-write support; then activate in one transaction that locks the
global row and workshop leases in canonical order and proves there is no
in-flight legacy writer or quarantine. Old flat mutation admission must be
disabled at activation, because rolling coexistence would allow an old binary
to rewrite a sealed selected generation whenever the global lease is idle.

Implement and verify writer support in this order: `route-project`, recovery
maintenance entry/exit, consolidation of the already staged startup publisher
onto the shared generation/reconciliation/retention engine, and finally
release maintenance/candidate protocol v2. Activation is one coordinated,
irreversible gate after every writer supports complete immutable generations
and every flat mutation admission is disabled. Activating `route-project`
alone would still let legacy recovery or release mutate its selected sealed
generation later. The dormant release filesystem foundation does not shorten
or bypass this order. Migration 0026 now provides the narrow dormant database
state machine through `awaiting_worker_finalize`; active release v2 and its
whole-release finalizer remain pending.

Route-overlay status correction (2026-08-22): recovery maintenance is a durable,
projection-derived overlay under migration 0013. Release maintenance remains a
fenced but byte-derived overlay that saves and later restores
`.recovery.bak`; it is not evidence that the overlay portion of ADR 0009 is
complete. Recovery's database authority is durable, but its current filesystem
writer must still move to the shared copy-on-write publisher. Replace release
maintenance with a projection-derived durable release overlay only after the
route-project, recovery, and startup publication stages above; then activate
release protocol v2 before marking the ADR fully implemented.

Regardless of the selected option:

- every child lookup/update/delete includes the owning workshop predicate;
- integration commands carry the validated workshop identity explicitly;
- runtime roles retain least privilege;
- tests attempt cross-tenant reads and writes directly through every runtime
  database role.

Acceptance criteria are defined by the ADR and must include a direct database
cross-tenant test. Do not claim database-enforced isolation until that test is
running in CI.

Implemented rehearsal tenant-isolation slice (2026-08-24): the rehearsal
ledger now uses forced, command-specific RLS. Platform status/metrics and the
scheduler's bounded discovery retain explicit fleet-wide read policies; API
mutation grants are removed, while scheduler insert/update require the exact
transaction-local workshop context and matching recovery parent. Missing,
malformed, and cross-workshop contexts fail closed in the production-role
PostgreSQL matrix. No runtime delete policy exists.

Implemented recovery-point ACL preparation (2026-08-24): the release worker no
longer has stale direct SELECT/INSERT/UPDATE access to the recovery-point
ledger, and the privacy worker no longer has stale direct SELECT access. Their
production modules contain no direct recovery-point SQL. Release review keeps
only its bounded fixed-search-path `SECURITY DEFINER` function, and live role
tests prove the removed table operations fail with PostgreSQL privilege errors.
This narrows the next Phase 2 review to the platform API's mixed fleet release
and status behavior plus the driver ledger's bounded fleet release read; it
does not yet enable RLS on the recovery-point parent.

Implemented platform recovery-point capability slice (2026-08-24): platform
status and metrics retain read-only fleet visibility, while migration
`0044_platform_recovery_capabilities` removes direct recovery-point
INSERT/UPDATE/DELETE from `control_api`. Final deletion backups and pre-release
fleet backups now use separate fixed-search-path `SECURITY DEFINER`
capabilities. Each validates its exact durable operation and derives the row's
tenant ownership and security-sensitive fields from authoritative ledger state;
the Rust calls stay within the existing deletion or fleet-adoption transaction.
Static and production-role tests prevent direct platform writes, PUBLIC
execution, or a return to inline table inserts. At this point the remaining
recovery-parent blocker was the driver ledger's bounded fleet-release read.

Implemented driver recovery-read capability slice (2026-08-25): migration
`0045_driver_recovery_read_capabilities` replaces both fleet-wide driver reads
of recovery points with separate, bounded, fixed-search-path
`SECURITY DEFINER` capabilities. Normal release preparation must present the
exact live control-operation, driver, global-resource, and fleet fence tuple;
forward reconciliation must present its exact live observation claim plus the
quarantined original release identity. Stale or mismatched authority fails with
a privilege error, and both result sets remain capped at 501 rows. The direct
driver SELECT/UPDATE grant remains temporarily because tenant-scoped backup,
restore, and progress operations still use it. The next Phase 2 step is the
final forced-RLS policy and privilege matrix for that tenant workflow.

Implemented recovery-point forced-RLS slice (2026-08-25): migration
`0046_recovery_point_tenant_rls` enables and forces RLS on
`workshop_recovery_points`. Platform status and scheduler discovery retain
explicit fleet-wide read policies; tenant API reads/inserts, lifecycle
reads/updates, scheduler inserts, and driver reads/updates require the exact
transaction-local workshop context. No runtime delete policy exists, and the
lifecycle worker's unused INSERT/DELETE privileges are removed. The platform
write and driver fleet-read capabilities remain usable through the migration
owner policy without restoring table-wide runtime authority. The production-
role PostgreSQL matrix now proves missing, malformed, and cross-workshop
contexts fail closed for the recovery parent.

## 6. Phase 3 — complete typed startup configuration

### 6.1 Inventory and classify

Inventory every `std::env::var` and `var_os` read and classify it as:

- required process configuration;
- optional process configuration with a documented default;
- secret reference;
- telemetry/runtime convention owned by a library;
- test-only configuration.

Reconcile the inventory with `deploy/configuration-spec.json`. Being read at a
later point in the code is not by itself a startup-gate defect; a defect exists
when a process can start and only later discover missing or malformed
configuration it needs.

### 6.2 Parse once per executable

Create typed configuration for each executable or worker class. Parse URLs,
socket addresses, durations, limits, enums, paths, and secret references at
startup. Application, worker, and integration modules receive typed values and
must not read the environment directly.

Implemented worker slice (2026-08-22): `control-worker` loads and validates its
PostgreSQL URL, immutable release identity and, only for hostname-building
worker classes, its tenant DNS suffix before telemetry or database connection.
The typed values are passed
through the worker dispatch boundary; reconciliation, module, domain and invoice
paths no longer rediscover either setting at point of use. A unit test keeps the
queue-specific tenant-domain ownership aligned with
`deploy/configuration-spec.json`.

Extended worker slice (2026-08-22): invoice and inventory queues now own typed,
bounded monthly usage limits and Azure submission pacing, while invoice capture
also owns its validated optional Paperless tag IDs. The privacy queue parses its
driver URL, bearer secret, and optional Unix socket once at startup and passes
them through dispatch. Extraction and privacy operation paths no longer read
these immutable settings from the environment.

Email worker slice (2026-08-22): the email queue now validates the exact private
mail-gateway route, its bearer, the public root origin, invitation key ID and
absolute signing-ring path before telemetry or database connection. It builds
one proxy-disabled, redirect-disabled HTTP transport per worker process and
adds authentication to the exact request at delivery time. Invitation delivery
reloads only the already validated key-ring path, preserving atomic online key
rotation and retained-key signing for queued generation-pinned outbox rows;
delivery code no longer reads process configuration or constructs clients.

Implemented backup-scheduler slice (2026-08-22): the scheduler parses its
database and deployment-driver URLs, release identity, secret credentials,
optional Unix socket, strict enable flag, and bounded poll interval before
telemetry or I/O initialization. Defaults (disabled and 3,600 seconds) and
invalid optional values are covered by focused tests and operator documentation.

Allow direct environment access only in:

- the configuration loader;
- `runtime_secret` for its documented secret-resolution boundary;
- telemetry initialization for standard OpenTelemetry variables;
- tests with an explicit reason.

Add a source or lint gate enforcing this allowlist. Extend the machine-readable
specification if optional settings and defaults need to be represented; do not
mislabel optional tuning as required secrets.

Acceptance criteria:

- every release executable has a typed startup configuration test;
- missing required values and invalid optional values fail before work starts;
- defaults are documented and tested;
- application paths contain no unapproved direct environment reads;
- `configuration-spec.json`, release metadata, Compose, and documentation agree.

## 7. Phase 4 — tracing, logging, and metrics

### 7.1 Correlation model

Adopt one correlation model across HTTP and durable work:

- accept a valid inbound request ID or generate one;
- return it in the response;
- create one HTTP span per matched route;
- persist W3C `traceparent`/`tracestate` when admitting a durable operation;
- attach the persisted parent when a worker leases that operation;
- inject trace context into supported outbound HTTP calls.

Keep the existing durable-operation trace propagation and add tests around it
rather than replacing it.

### 7.2 Span and event fields

Use stable, low-cardinality field names. HTTP spans should include method,
matched route, response status, request ID, trace ID, and latency. Durable
operation spans should include operation ID, operation kind, queue, attempt,
reconciliation state, and safe outcome class.

Add `workshop_id`, resource ID, provider, and authority decision only where they
help diagnose that operation. Never use raw URL paths, hostnames, email
addresses, idempotency keys, tokens, authorization headers, cookies, request or
response bodies, secret references, document contents, or arbitrary provider
errors as metric labels.

Instrument application operations and external adapter calls, not every helper
function. Avoid duplicate handler and middleware spans for the same unit of
work.

### 7.3 Severity and error policy

- `ERROR`: terminal internal failure, invariant violation, or failed recovery
  that requires operator action.
- `WARN`: rejected trace context, degraded dependency, retry exhaustion
  approaching, or a security-relevant refusal worth investigation.
- `INFO`: process lifecycle, admitted/completed durable operation, and
  infrequent administrative state transition.
- `DEBUG`: bounded diagnostic detail useful during investigation.

Expected client errors such as validation failures, missing resources, and
ordinary forbidden responses are not application errors. Record their response
status on the HTTP span without emitting an error event.

Internal errors are logged once as a bounded chain of stable source classes;
raw `Display`/`Debug` chains are never a logging contract because database
details, URLs, paths, and context strings can contain protected values. Public
responses remain redacted. Provider response bodies are never logged.

### 7.4 Metrics and telemetry operation

Keep metric dimensions bounded. Use matched routes and status classes, never
raw paths or identifiers. At minimum expose:

- request count and latency by route/status class;
- operation admissions, completions, retries, dead letters, and lease loss by
  operation kind;
- queue age and in-flight count;
- outbound dependency latency/failure by provider and operation;
- trace-export failure and dropped telemetry indicators where supported.

Document local JSON logging, production filters, OTLP opt-in behavior, shutdown
flush, and sampling. Telemetry export failure must not crash request handling,
but startup misconfiguration should fail clearly when export is explicitly
enabled.

Acceptance criteria:

- one integration test follows an HTTP request into a durable worker span;
- request IDs are returned and propagated;
- HTTP completion spans include status and latency, including failures;
- redaction tests prove representative tokens, email addresses, payloads, and
  secret paths do not appear in captured logs;
- metric-cardinality tests use matched routes and bounded labels;
- orderly shutdown flushes the telemetry provider.

Implemented logging slice (2026-08-22): API, durable-worker,
deployment-driver, mail-gateway, extraction-broker, backup-scheduler, and
executable lifecycle boundaries emit only closed outcome/error/resource
classes plus operationally necessary opaque UUIDs and numeric values.
Pre-telemetry startup failures use fixed machine-readable stage classes instead
of allowing `anyhow` chains to be printed by `main`. Captured subscriber tests
inject bearer, email, hostname, request/provider payload, trace metadata, and
mounted-secret-path canaries. `tools/test_log_safety.py` rejects raw errors,
sensitive fields, whole-object debug formatting, and raw `Result`-returning
binary entrypoints.

## 8. Phase 5 — outbound HTTP policy and adapters

Reuse `reqwest::Client`; it is internally pooled and cheap to clone. Do not
construct a client inside a request handler or operation attempt.

Create a small client factory or explicit client profiles that centralize only
genuinely shared policy:

- Rustls and trust-root policy;
- connect timeout;
- redirect policy;
- user agent;
- proxy behavior;
- trace propagation and safe request instrumentation.

Keep total request timeout, response-size limits, retry policy, and provider
authentication with the integration adapter because those requirements differ.
Name profiles by behavior, not by arbitrary timeout (`ExternalApiClient`,
`LongRunningExtractionClient`, and similar). Document every exception.

Retries belong at the operation/integration policy layer, not in a generic HTTP
client. Retry only replay-safe requests or requests protected by an external
idempotency contract. Preserve unknown outcomes.

Acceptance criteria:

- no request path constructs a new Reqwest client;
- every adapter has explicit connect/total timeout and redirect behavior;
- outbound trace propagation is tested with a mock server;
- retry and idempotency behavior is tested independently of transport setup.

Implemented worker slice (2026-08-22): Odoo and Paperless calls share
process-scoped internal-service pools while preserving their distinct caller
identities. Their workshop-specific credentials, Odoo database filter, and
operation-specific total timeout are applied to each request, never installed
as client defaults. Email delivery also owns one process-scoped internal client
through its queue configuration. Rauthy, Cloudflare custom-hostname, and
Scaleway TEM adapters each own one process-scoped external transport pool with
their existing caller identity, proxy and redirect policy; provider credentials
and adapter total timeouts remain request-local. Extraction-broker adapter
objects created during worker attempts now clone one internal no-proxy process
pool; their bearer credential and operation-specific total timeout remain
request-local. Container startup and release Odoo readiness loops likewise
reuse one process transport while retaining their distinct total-timeout
semantics. Deployment calls now use queue-owned, startup-validated clients for
provisioning, reconciliation, lifecycle, and release workers; privacy export
calls use the privacy queue's own process client. The API owns one driver client
for carrier-secret and recovery handlers. In each case the bearer remains a
sensitive request-local header, Unix-socket routing and no-proxy behavior are
preserved. Queue/adapter configuration owns total timeouts while the operation
layer retains trace context, idempotency, retry decisions, and
ambiguous-outcome classification. A source
gate rejects new production Reqwest constructors outside the reviewed outbound
HTTP policy boundary. Phase 5's transport-lifetime criterion is therefore met;
provider retry/idempotency behavior remains owned and tested by the operation
and integration layers rather than hidden in the shared transports.

## 9. Phase 6 — generated frontend contracts

Replace route-local interfaces that duplicate generated API models with imports
from `web/src/lib/generated/control-api.ts`. Start with shipping, domains, email
domains, SMTP, and webshop onboarding.

If a view needs derived UI state, define a view model with a different name and
an explicit conversion from the generated transport type. Do not silently
redeclare the server response shape. Improve imprecise generated `unknown` or
string fields at the Rust/OpenAPI source when practical.

Acceptance criteria:

- no frontend type shadows a generated response type;
- backend field changes fail the generated-client freshness or frontend type
  check;
- generated files are changed only through the generator.

Typed provider-evidence slice (2026-08-22): custom-domain edge validation
records and branded-email DNS/verification maps are projected at the Rust API
boundary into explicit allowlisted response types. Arbitrary provider fields
and malformed entries no longer flow through an OpenAPI `unknown`; the
generated TypeScript client carries the exact nested record types and the
domains page consumes those transport types directly without local shadow
interfaces or runtime shape reconstruction.

The architecture source gates for tenant query predicates, transaction-only
worker capabilities, lifecycle effect ordering, environment access, outbound
HTTP construction, privacy deployment and log safety now run in the required
CI job as well as the local Makefile. The lifecycle checker models deletion
route tombstones, restore maintenance, and the primary lifecycle effect as
separate ownership-before-I/O phases.

## 10. Phase 7 — focused mechanical cleanup

After the risk-reduction phases are stable:

1. Consolidate the repeated worker terminal/failure transition branches behind
   a typed outcome function without hiding lifecycle-specific compensation.
2. Remove obsolete files only after confirming their owning repository,
   deployment path, and recovery implications.
3. Correct factual counts and path references in `review-note.md` or archive it
   as review input once its accepted findings are tracked here.

Do not turn deduplication into a broad framework migration. Similar-looking
code may encode different retry, timeout, compensation, or security policy.

## 11. Delivery order and review gates

Use this order:

1. Baseline, threat model, and route inventory.
2. Route access policy and `WorkshopScope`.
3. Cross-tenant HTTP tests.
4. Database-isolation ADR and selected defense.
5. Typed startup configuration.
6. Request correlation, tracing, logging redaction, and bounded metrics.
7. Reusable HTTP client profiles.
8. Generated frontend type adoption.
9. Focused cleanup.

Every pull request must include:

- the invariant it establishes;
- tests that fail without the change;
- migration and rollback notes where state changes;
- observability impact and any new fields;
- confirmation that no secret or personal-data field was added to logs;
- regenerated contracts when applicable;
- `cargo fmt`, Clippy with warnings denied, Rust tests, frontend checks, and the
  relevant PostgreSQL/integration gates.

The tenant-authorization change is not complete merely when the duplicated
helpers disappear. It is complete only when route construction enforces the
declared policy and the cross-tenant matrix proves the behavior. Likewise,
observability is not complete merely when spans exist; operators must be able to
correlate a request, its durable operation, its external dependency call, and
its terminal outcome without inspecting sensitive payloads.
