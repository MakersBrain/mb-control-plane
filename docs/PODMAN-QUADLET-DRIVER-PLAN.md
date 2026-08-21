# Podman/Quadlet deployment-driver plan

Status: proposed, design review incorporated

Repositories:

- `mb-control-plane`: authenticated driver contract, durable operation logic,
  desired-state reconciliation and the Docker development backend;
- `mb-infra`: production placement, host identity, Quadlet rendering, rootless
  systemd integration and deployment qualification.

## 1. Objective

Replace the current production Podman compatibility-socket implementation with
a rootless, systemd-managed Quadlet backend without changing the authenticated
control-plane driver contract.

Before introducing Quadlet, repair Docker reboot behavior and extract one
backend-neutral desired-state reconciler. Docker and Quadlet must implement the
same resource, idempotency, recovery and readiness semantics even though their
runtime mechanisms differ.

The final design must ensure:

- Docker remains a development-only backend;
- staging and production do not mount `docker.sock` or `podman.sock` into an
  application container;
- long-running Paperless and Odoo runtime resources survive host reboot;
- only the recorded active Odoo slot returns after reboot;
- one-shot jobs never restart automatically;
- missing dynamic containers or units can be reconstructed from non-secret
  durable intent and protected secret files;
- static platform rollback does not delete dynamic tenant resources;
- the driver remains able to accept repair commands while a managed tenant
  runtime is degraded;
- public tenant traffic remains on a validated maintenance route until runtime
  reconciliation completes;
- control-plane and host-agent journals converge after every interruption
  without requiring a distributed transaction;
- the active and retained previous control/agent protocol versions and release
  grants remain compatible throughout the rollback window;
- every backend passes the same driver contract and failure-recovery suite.

## 2. Current state and gap

`control-container-driver` and `control-docker-driver` currently execute the
same Rust implementation. The selected `DRIVER_CONTAINER_RUNTIME` changes the
Docker-compatible API version and socket, but does not change the orchestration
model.

In development, Docker Compose manages static services with
`restart: unless-stopped`. Dynamic Paperless containers and Odoo blue/green
runtime containers are created through the Docker Engine API without an
explicit restart policy, so Docker applies its default `no` policy. Their
volumes and secret files survive a reboot, but the containers remain stopped.

Driver startup currently:

- removes stale job-secret directories;
- repairs interrupted PostgreSQL connection limits;
- repairs retained maintenance route files.

It does not perform a complete reconciliation of Paperless resources, active
Odoo slots, restart policies or gateway routing before reporting liveness.

In staging and production, `mb-infra` runs the driver in a Quadlet container
that mounts the rootless Podman API socket. The driver creates long-running
tenant containers through Podman's Docker compatibility API, leaving those
containers outside systemd/Quadlet ownership. `mb-infra` also renders a static
`odoo.service`, while the release driver creates `mb-odoo-blue` and
`mb-odoo-green`, resulting in conflicting runtime ownership.

## 3. Target architecture

```text
control workers
      |
      | authenticated HTTP + idempotency key
      v
control-container-driver                    mb-control-plane
      |
      | versioned, authenticated Unix protocol
      v
makersbrain-quadlet-agent                   mb-infra host user service
      |
      +-- atomic Quadlet generation
      +-- systemctl --user lifecycle
      +-- typed one-shot jobs
      +-- platform-release allowlist
      +-- local action journal
             |
             v
rootless Podman + user systemd
      +-- Odoo blue/green Quadlets
      +-- per-workshop Paperless Quadlets
      +-- per-workshop volume Quadlets
      +-- transient job Quadlets
      +-- static mb-infra release Quadlets
```

The control plane decides which tenant operation is required. Infrastructure
alone decides how an approved operation becomes a rootless Quadlet/systemd
resource.

### 3.1 Ownership

| Concern | Owner |
| --- | --- |
| Public driver HTTP routes and payload semantics | `mb-control-plane` |
| Command admission, desired state and control PostgreSQL ledger | `mb-control-plane` |
| Tenant provisioning, recovery and fleet release logic | `mb-control-plane` |
| Backend-neutral desired-state reconciler | `mb-control-plane` |
| Docker development backend | `mb-control-plane` |
| Versioned Quadlet-agent client | `mb-control-plane` |
| Host-agent service and Unix socket | `mb-infra` |
| Dynamic Quadlet templates and policy validation | `mb-infra` |
| Idempotent host-effect journal and systemd execution | `mb-infra` |
| Active/retained platform execution-grant set | composed releases in `mb-infra` |
| Staging and production qualification evidence | `mb-infra` |

## 4. Phase 0: Docker reboot safety and desired-state foundation

This is the first implementation milestone. It fixes an existing development
reboot gap and creates the semantic foundation for Quadlet.

### 4.1 Persist reconstructable runtime intent without a second authority

Restart policies can restart an existing container but cannot recreate a
missing one. Persist one non-secret desired specification for every long-lived
dynamic resource.

Do not introduce an independently writable generic intent table. Extend the
existing domain records and expose one read-only projection to the driver:

1. `control.service_instances` remains authoritative for tenant services. Add
   closed `desired_runtime_state`, `runtime_spec`, `runtime_spec_digest` and
   `runtime_generation` fields for Paperless. Constrain state to `running`,
   `stopped` or `absent`, require a positive monotonically increasing
   generation and validate the JSON structure in application admission plus a
   database shape check.
2. `control.runtime_release_slots` remains authoritative for Odoo slots. Its
   existing slot state maps to runtime intent; do not copy it into another
   independently writable table.
3. Create a read-only `control.driver_runtime_intents` view that normalizes the
   two sources into `resource_key`, `resource_kind`, `desired_state`,
   `specification`, `specification_digest` and `generation`.
4. Store backend observations separately in a driver-owned
   `control.runtime_resource_observations` table. Observations can never change
   desired state and are replaceable evidence, not authority.

The API or owning worker writes domain state and its runtime specification in
the same PostgreSQL transaction that admits the corresponding durable
operation. The provisioning, reconciliation and lifecycle workers own
Paperless desired-state transitions. The release worker owns Odoo slot
transitions. The driver receives `SELECT` on the normalized intent view and
bounded insert/update rights on observations only.

Every transition uses compare-and-set on `runtime_generation`. The reconciler
reads a generation, acquires the resource lock, rereads the row and abandons
the stale action if the generation changed. Database constraints and tests must
prove that one resource key maps to one authoritative domain record.

For Paperless, persist:

- workshop ID;
- deterministic container and volume names;
- database name and database role;
- Redis username and key/channel prefix;
- public hostname;
- OIDC client ID;
- digest-pinned image reference outside development;
- expected secret paths and secret-boundary version;
- configuration digest computed only from non-secret specification fields;
- desired state.

Database passwords, Redis passwords, OIDC secrets, Django secrets, admin
passwords and bridge credentials remain only in protected tenant secret files.
The specification contains their expected paths and secret generation IDs,
never their values or unkeyed hashes of their values. Secret rotation advances
the generation and therefore the non-secret configuration digest. If a value
must be compared during a transition, compare it in memory or use a keyed MAC
whose key is not stored in PostgreSQL; do not persist a reusable credential
verifier.

Odoo reconstruction should use existing application-release manifests,
`runtime_release_slots`, extension-volume records and protected release
configuration files. Persist only additional non-secret information required
to recreate an identical container.

Existing successful service rows must be backfilled before enabling boot
reconstruction. A first-time provision that creates an external resource but
disconnects before the worker commits its result remains recoverable through
the existing operation and backend host-effect idempotency record (the Docker
driver ledger initially, the agent journal later); boot reconciliation must not
invent a desired resource absent from authoritative domain state.

### 4.2 Add explicit Docker restart policies

Update dynamic container creation in `src/docker_driver/services.rs` and
`src/docker_driver/release.rs`.

| Resource | Restart policy |
| --- | --- |
| Paperless with desired state `running` | `unless-stopped` |
| Active Odoo slot | `unless-stopped` |
| Candidate Odoo slot | `no` while prepared or verified |
| Retained, inactive or failed Odoo slot | `no` |
| Migration, backup, restore and initialization jobs | `no` |

Add a Docker backend operation that updates an existing container's restart
policy. During an Odoo activation:

1. prepare and verify the candidate with restart policy `no`;
2. persist the activation intent;
3. place tenant ingress behind the validated cutover/maintenance gate;
4. set the candidate container to `unless-stopped` and observe that policy;
5. atomically activate and verify gateway routes;
6. mark the new slot active and the old slot retained in one database
   transaction;
7. set the old container to `no` and observe that policy;
8. open the traffic gate only after the database state, gateway digest and new
   runtime observation agree;
9. stop the old container when its retention state permits it.

The persisted activation intent records each boundary. The reconciler repairs
restart-policy or route drift if the process terminates between steps. Until it
does, ingress remains on maintenance or the last completely committed route;
it must never expose a route whose selected runtime is not observed healthy.

### 4.3 Add a backend-neutral boot reconciler

Extract a shared runtime boundary, for example:

```text
src/container_runtime/
  mod.rs
  observation.rs
  reconcile.rs
  docker.rs
  quadlet_agent.rs     added in a later phase
```

Run boot reconciliation after the existing connection-limit and maintenance
route repairs and before driver readiness.

The reconciler must:

1. load the recorded active Odoo slot;
2. inspect both deterministic Odoo slot resources;
3. ensure exactly the active slot is running and reboot-enabled;
4. keep retained, inactive and failed slots stopped;
5. load Paperless runtime intents;
6. ensure every `running` Paperless resource exists, matches its specification
   digest and becomes healthy;
7. keep `stopped` resources stopped;
8. report unknown or orphaned resources without automatically deleting them;
9. validate and restore the intended gateway route digest;
10. reconcile interrupted database limits and maintenance routes;
11. remove abandoned job secrets only after proving no corresponding job is
    running;
12. record a completed reconciliation generation.

If a long-running container is missing, recreate it from the persisted
non-secret specification. Require all referenced volumes and secret files to
exist. A missing secret, image, volume or release identity is a fail-closed
error; boot reconciliation must never generate replacement credentials.

If no valid active Odoo slot exists, the driver remains command-ready so an
authorized release or recovery action can repair it, but tenant ingress remains
on maintenance. A pristine installation with no provisioned workshop and no
active application release is reported separately from a degraded established
installation.

### 4.4 Add periodic reconciliation

Startup reconciliation alone does not handle a Docker daemon restart while the
driver process remains alive.

Add a background loop that:

- runs at a bounded 30-60 second interval;
- uses mandatory per-resource locks for Paperless and individual slots plus a
  fleet-wide lock only for route/slot activation;
- retries with exponential backoff while Docker is unavailable;
- reconciles immediately after the Docker socket reconnects;
- does not mutate a resource owned by an in-flight fleet, lifecycle or recovery
  action;
- records drift and repair metrics without secret values.

The loop must not hold a global lock while waiting for container health. It
reads the desired generation, acquires the narrow lock, rereads the generation,
performs the mutation and releases the lock before long observation polling
where safe. A final generation check prevents stale observations from being
committed.

Every successful action should also reconcile and observe the affected
resource before returning.

### 4.5 Driver readiness

Keep `/health/live` process-only. `/health/ready` answers whether the driver can
accept, journal and reconcile commands; it must not become false merely because
a managed Odoo or Paperless resource is degraded. Driver readiness requires:

- the driver ledger is reachable;
- PostgreSQL administration is reachable;
- the selected runtime backend is reachable;
- the initial intent scan completed and the reconciliation loop is running;
- the host-agent protocol is compatible when that backend is selected;
- the driver can read desired generations and write operation/observation
  records.

Expose managed-resource convergence separately through metrics and an
operator-only `/health/runtime` report. A degraded active slot, stale gateway
digest or unresolved activation intent keeps the public traffic gate closed and
raises alerts, while the driver stays available for release, lifecycle and
recovery commands.

Change the Docker Compose driver health check from `/health/live` to
`/health/ready`.

### 4.6 Public traffic boot gate

Introduce a backend-neutral runtime traffic gate. On boot, the gateway serves a
validated maintenance configuration until the reconciler proves that the
recorded active slot, observed container/unit, image identity and route digest
agree. The reconciler then atomically installs the active routes and reloads the
gateway.

For Quadlet, add a `makersbrain-runtime-ready.target` or equivalent convergence
marker. Before the gateway starts, a one-shot initializer must replace any
persisted tenant route selection with the validated maintenance configuration;
the agent may select active tenant routes only after reaching the marker.
`cloudflared` may start earlier so operator, API and authentication routes remain
available for repair, but its tenant-gateway origin sees maintenance until the
gate opens. Nothing should order the complete tunnel behind Odoo health.

On loss of convergence after boot, switch tenant routes back to maintenance
before attempting destructive repair. Test the window between gateway startup,
driver startup and active-slot reconstruction explicitly.

### 4.7 Docker reboot tests

Unit and adapter tests must prove:

- dynamic create bodies use the correct restart policy;
- one-shot jobs always use `no`;
- an existing stopped Paperless container restarts;
- a missing Paperless container is reconstructed from intent and existing
  secret files;
- a missing secret blocks reconstruction;
- exactly the active Odoo slot starts;
- retained and inactive slots remain stopped;
- two active slots or another ambiguous state fail closed;
- unknown resources are reported but not deleted;
- reconciliation is idempotent;
- restart-policy drift is repaired;
- gateway routes are restored before the tenant traffic gate opens;
- the driver remains command-ready while tenant ingress is gated for a failed
  active runtime;
- cloud/tunnel ingress cannot reach a stale tenant route during boot;
- interruption at each blue/green transition converges to the durable intent.

Add a live Docker reboot/restart test that:

1. provisions two Paperless workshops and one active Odoo slot;
2. restarts Docker;
3. verifies automatic restart and isolation;
4. removes one disposable Paperless container without removing its volumes;
5. restarts the driver;
6. verifies reconstruction from the durable intent;
7. confirms one-shot containers do not return.

## 5. Phase 1: freeze the driver contract

Make the existing authenticated HTTP contract executable and backend-neutral.

Define request and response fixtures for:

- `provision`;
- `reconcile`;
- `lifecycle`;
- `rehearse`;
- `download`;
- `release`;
- `resume`;
- `erasure`;
- `restrict`;
- `carrier-secret`;
- `carrier-secret-delete`;
- privacy export.

Capture bearer authentication, `idempotency-key`, payload-digest conflict,
timeout and safe-error behavior. Add a conformance runner that can target the
Docker driver or a staging Quadlet driver.

Preserve current opaque secret references such as `docker/<workshop>/...`
during this migration. Renaming persisted references belongs to a separate
schema-epoch decision.

## 6. Phase 2: extract runtime interfaces

Move raw Docker operations behind internal interfaces:

- `PersistentRuntime`: ensure/remove/start/stop and inspect Paperless and Odoo
  services;
- `JobRuntime`: run Odoo, PostgreSQL, backup, restore and volume jobs;
- `VolumeRuntime`: ensure, inspect and retention-gated deletion;
- `ImageRuntime`: prove exact image presence and normalized OCI identity;
- `GatewayRuntime`: validate, reload and observe a route digest.

Do not expose raw Docker inspect JSON above the backend. Use normalized
observations such as:

```text
RuntimeObservation
  resource_key
  desired_digest
  observed_digest
  image_digest
  service_name
  active_state
  health_state
  runtime_object_id
```

Keep the current Engine implementation as `DockerRuntimeBackend`. The shared
reconciler must consume only the interfaces above.

Configuration changes:

- add `DRIVER_BACKEND=docker|quadlet-agent`;
- add `DRIVER_AGENT_SOCKET` and a file-backed `DRIVER_AGENT_TOKEN`;
- retain `DRIVER_CONTAINER_RUNTIME` and `DRIVER_RUNTIME_SOCKET` only for the
  Docker compatibility backend;
- reject the Docker backend outside development after staging migration;
- update `configuration-spec.json`, `release-contract.json`, secret staging and
  agreement tests in the same release.

## 7. Phase 3: implement the `mb-infra` Quadlet agent

Add infrastructure-owned rootless user units:

```text
makersbrain-quadlet-agent.socket
makersbrain-quadlet-agent.service
```

Run them as `tenant-runtime`, outside a container, with:

- `HOME=/home/tenant-runtime`;
- the correct `XDG_RUNTIME_DIR`;
- access to the user systemd bus;
- no TCP listener;
- a mode-`0600` Unix socket mounted only into the driver container;
- a distinct agent credential;
- no control database, Rauthy, mail, cloud-backup or tenant business
  credentials.

The protocol must be typed and closed. It must not accept arbitrary commands,
arbitrary Quadlet text, arbitrary environment keys or arbitrary host paths.

Suggested operations:

- `capabilities`;
- `ensure_paperless`;
- `remove_paperless`;
- `ensure_odoo_slot`;
- `set_resource_state`;
- `run_job`;
- `ensure_volume`;
- `inspect_resource`;
- `reload_gateway`;
- `reconcile`.

Each request includes a protocol version, action ID, idempotency key, canonical
request digest, resource key and typed desired state.

For every request, the agent must:

1. authenticate the caller;
2. validate the operation-specific allowlist;
3. check its local action journal for replay or digest conflict;
4. render into a temporary generation;
5. run Quadlet generator and systemd verification;
6. atomically install the generation;
7. call `systemctl --user daemon-reload`;
8. start, reload or stop the exact derived unit;
9. wait for bounded readiness;
10. persist observed evidence before replying.

Use argv-based subprocess execution only. No request value may be interpolated
into a shell command.

### 7.1 Control-ledger and agent-journal crash protocol

The two journals have distinct authority and do not attempt a distributed
transaction:

- the control PostgreSQL ledger owns command admission, public idempotency and
  the durable operation outcome;
- the agent journal owns whether one exact host-side effect was accepted,
  applied and observed;
- desired domain state remains in control PostgreSQL; the agent journal never
  changes it.

Use the same stable `action_id`, idempotency key and canonical request digest
at both layers. The execution sequence is:

1. the control driver durably admits the operation before contacting the agent;
2. the agent rejects a reused key or action ID with a different digest;
3. the agent persists and fsyncs an `accepted` record before the first host
   mutation;
4. it advances through `applying` and persists a normalized observation;
5. it fsyncs `succeeded` before sending a success response;
6. only then does the control driver commit its successful response.

If the response is lost after step 5, a retry returns the stored agent result
without repeating the effect. If the agent fails before it can prove that no
effect occurred, its record remains non-terminal and the control operation
stays `awaiting_reconciliation`; neither layer may convert an ambiguous result
to an ordinary failure. On restart, the agent inspects the exact unit/job and
either completes the existing record or returns bounded reconciliation
evidence. A safe terminal failure is permitted only when the agent proves the
effect did not occur or completed rollback to the prior observed generation.

Journal records include protocol version, policy version, action ID, request
digest, resource key, previous and desired generation, state, normalized
observation and timestamps. They contain no request secret, environment value,
raw subprocess output or unrestricted path. Journal writes use atomic replace,
`fsync` of the file/database and containing directory, or SQLite with full
durability settings. Host replacement can rebuild desired resources from
control PostgreSQL; retaining the journal is required for the normal rollback
and ambiguous-outcome window but it is not a second desired-state authority.

### 7.2 Agent artifact and protocol lifecycle

The agent is an immutable component of the composed platform release. Record
its source digest, installed artifact digest, policy version, protocol minimum
and protocol maximum. Install it under a versioned path such as:

```text
/opt/makersbrain/quadlet-agent/<artifact-digest>/
```

Select the active version with an atomic symlink used by the user service.
Retain the previous artifact for the complete application rollback window.

Each platform deployment follows this order:

1. verify that the currently installed agent supports the candidate control
   client's protocol, or that the candidate agent supports both the current
   and candidate clients;
2. install and start the candidate agent while the current control release is
   still active;
3. run capability, policy and no-mutation probes through both current and
   candidate protocol fixtures;
4. activate the candidate static Quadlet release;
5. retain the previous control and agent pair until the rollback window closes.

Automatic rollback first restores an agent version compatible with the
previous control client, then restores the previous static Quadlet release.
Every release must support the immediately previous protocol during the
rollback window. A breaking protocol change therefore requires an explicit
expand/migrate/contract sequence across at least two platform releases.

## 8. Phase 4: dynamic Quadlet storage layout

Keep immutable static releases and dynamic tenant resources separate:

```text
~/.config/containers/systemd/
  makersbrain -> immutable static platform release
  makersbrain-dynamic/
    tenants/<workshop-id>/
    odoo-slots/
    volumes/
```

Put transient jobs below:

```text
$XDG_RUNTIME_DIR/containers/systemd/makersbrain-jobs/<action-id>/
```

This ensures:

- static release rollback does not delete tenant units;
- durable tenant resources survive reboot;
- interrupted one-shot jobs do not restart automatically;
- unit names derive only from validated UUIDs and fixed prefixes;
- every generated file has a recorded SHA-256 digest.

Removing a Quadlet source file is not resource deletion. The agent must stop
the generated service, verify it is inactive, remove the source generation,
run `daemon-reload`, verify the generated unit is gone and reset any obsolete
failed state. Podman volume deletion is a separate, explicit operation allowed
only after the control-plane retention gate; removing a `.volume` file must
never be treated as deletion of its data.

Use deterministic service names:

```text
mb-paperless-<compact-workshop-id>.service
mb-odoo-blue.service
mb-odoo-green.service
mb-driver-job-<action-id>.service
mb-paperless-data-<compact-workshop-id>-volume.service
```

## 9. Phase 5: migrate Paperless

Port Paperless first because it is tenant-scoped and does not switch the shared
Odoo fleet.

Each generated unit must contain:

- an exact digest-pinned image;
- the fixed MakersBrain rootless network;
- a deterministic container name;
- tenant-specific database and Redis identities;
- tenant-specific persistent volumes;
- a versioned, read-only secret subpath;
- a read-only root filesystem where supported;
- explicit writable paths and tmpfs mounts;
- dropped capabilities;
- a health check and restart policy;
- a configuration-digest label.

Reconciliation rules:

- missing unit: create and start from durable intent;
- identical digest: observe without replacement;
- changed digest: stop, atomically replace and start;
- failed health: retain the prior generation and return a retry-safe error;
- database, volume or secret identity drift: fail closed.

## 10. Phase 6: migrate transient jobs

Move PostgreSQL, Odoo initialization, extension materialization, backup,
restore and Paperless-volume jobs to transient Quadlets.

For every `job_kind`, define:

- allowed image source;
- exact command template;
- allowed scalar parameters;
- allowed volumes and secret mounts;
- timeout;
- bounded output size;
- cleanup policy;
- unknown-outcome retry classification.

The agent may accept only job-secret paths beneath the configured job-secret
root. Every referenced path must be a regular, non-symlink file.

### 10.1 Transient-job adoption and non-replay

An agent or driver restart does not imply that a transient systemd job stopped.
At startup, the agent must load every non-terminal journal record and inspect
the exact generated unit before accepting another request:

- a still-running matching unit is adopted and observed under its original
  action ID;
- a completed unit has its exit status and bounded evidence committed to the
  existing record;
- a missing unit with a proven pre-effect record can fail safely;
- a missing or indeterminate unit after the effect boundary remains unknown and
  requires operation-specific reconciliation.

Classify every job kind as replay-safe, externally reconcilable or
non-repeatable. Restore, erasure replay, database cutover and credential
rotation are never recreated merely because an HTTP request was retried.
Cleanup removes a transient unit and its job-secret directory only after the
journal is terminal and the unit is absent or observed stopped. Reboot and
agent-restart tests must cover a process termination before start, while
running, after exit and after durable success but before the response.

## 11. Phase 7: migrate Odoo slots and gateway ownership

Remove the ownership conflict between `mb-infra`'s static `odoo.service` and
the driver's blue/green runtime containers.

Final ownership:

- remove static `odoo.container` from the persistent platform-unit set;
- let the driver own `mb-odoo-blue` and `mb-odoo-green` through the agent;
- keep the Odoo data volume infrastructure-defined and persistent;
- allow the gateway to start without requiring static `odoo.service`;
- route only to the recorded active slot;
- keep tenant ingress on maintenance until a valid active slot exists while
  leaving the driver command-ready for authorized repair.

Map shared state consistently:

| Shared state | Docker | Quadlet/systemd |
| --- | --- | --- |
| Active | running and `unless-stopped` | active and boot-selected |
| Candidate | explicitly started, restart `no` | explicitly started, not boot-selected |
| Retained | stopped, restart `no` | stopped |
| Failed | stopped, restart `no` | failed/stopped pending reconciliation |
| Absent | remove after retention gate | remove generated unit after retention gate |

Add an `ExecReload` path to the gateway that validates its configuration,
reloads it and reports the observed digest. The driver calls the agent's typed
gateway operation instead of executing and signalling the gateway container
through the runtime API.

## 12. Phase 8: bind runtime actions to the composed release

The agent must not run an image merely because an authenticated driver request
names it.

Use a bounded set of composed platform releases as execution grants:

- materialize the active and retained previous release records in an
  agent-readable, read-only grant directory;
- admit only image digests present in the active record or a still-retained
  rollback record;
- require the exact qualified Odoo runtime/extension pair;
- require release ID, runtime subject, extension subject and qualification
  digest agreement;
- pre-pull and verify images through `mb-infra` before granting them;
- make online driver operations assert local image presence instead of pulling
  an unreviewed image.

Each grant records its activation and expiry boundary. A grant cannot be
removed while referenced by an active, candidate or retained Odoo slot, a
non-terminal job, a supported application rollback, or a recovery record that
requires its tooling. Grant garbage collection first proves those references
are absent and that the rollback window expired, then removes the grant and
eventually the unreferenced local image. Static rollback atomically reselects
the corresponding retained grant before restarting the previous control
release.

Extend cross-repository release agreement checks to cover:

- agent protocol version;
- dynamic Quadlet policy version;
- supported driver actions;
- configuration-spec digest;
- control image digest;
- admissible Odoo and extension subjects.

A platform record must be deployed before the release worker can activate an
Odoo pair absent from the current host grant.

## 13. Phase 9: update `mb-infra` deployment

The application release role must:

- verify and install the versioned agent artifact and atomically select a
  protocol-compatible version before application Quadlet activation;
- start the agent socket and pass current/previous-client compatibility probes;
- create agent state and dynamic Quadlet directories with mode `0700`;
- verify lingering and the user systemd bus;
- remove Podman socket ordering and mounting from
  `control-container-driver.container`;
- set `DRIVER_BACKEND=quadlet-agent`;
- mount only the agent Unix socket into the driver;
- remove static Odoo ordering after slot migration;
- install the maintenance route and runtime-ready traffic gate before removing
  static Odoo ordering;
- ensure `release.py` never removes the dynamic tree during static rollback;
- retain the previous agent artifact, execution grant and static release as one
  rollback set;
- protect and back up the agent journal for the idempotency/recovery window,
  while treating control PostgreSQL as the rebuild source for desired state;
  do not back up transient job units or job-secret directories;
- publish agent version, reconciliation generation and resource counts to
  deployment evidence and monitoring.

Remove `SecurityLabelDisable=true` if remaining mounts work with a narrow label
policy. If an exception remains necessary, document and test its exact scope.

## 14. Phase 10: existing resource migration and rollback

For each raw Podman resource:

1. inventory its container ID, image digest, mounts, volume names, health and
   labels;
2. render the equivalent Quadlet and compare the canonical desired digest;
3. stop the raw container without removing volumes;
4. remove only the raw container object;
5. install and start the Quadlet with the same deterministic resource names;
6. verify health, routing and secret isolation;
7. fsync successful adoption evidence in the agent journal;
8. return that evidence under the original action ID and let the control driver
   commit the durable operation result. A disconnect between these commits is
   resolved by replaying the stored agent result.

Keep the raw Podman backend available in staging for one release behind an
explicit emergency feature flag. Never fall back automatically after a partial
Quadlet operation because doing so can create duplicate resource ownership.

Transition rollback must:

- stop the generated service;
- restore the retained previous desired-state record;
- recreate a raw container only from that recorded specification;
- preserve all volumes and tenant secrets;
- record rollback as a new driver action.

After the staging evidence window, remove the production compatibility backend
and its Podman socket mount.

## 15. Verification gates

The migration is complete only when:

- Docker and Quadlet pass the same driver contract fixtures;
- no staging or production application container mounts a container-runtime
  socket;
- only the host agent writes the dynamic Quadlet tree;
- the agent rejects mutable tags, unapproved digests, traversal, symlinks,
  unknown environment keys, arbitrary commands and invalid resource names;
- two-workshop negative isolation tests pass for PostgreSQL, Redis, Paperless
  volumes, tenant secrets, gateway routes, backups and restores;
- driver or agent termination at every activation boundary reconciles to one
  owner and one observed result;
- a success persisted by the agent but disconnected before the control commit
  is replayed without repeating the host effect;
- ambiguous effects remain reconcilable and are never downgraded to an ordinary
  retryable failure;
- reboot restores durable Paperless and the active Odoo slot but not abandoned
  one-shot jobs;
- agent restart adopts a still-running transient job and never replays a
  non-repeatable job;
- static platform rollback leaves dynamic tenant units and volumes intact;
- static rollback restores a compatible retained agent and execution grant;
- both current and immediately previous control clients pass protocol probes
  against the candidate agent during the rollback window;
- blue/green activation survives failures before and after route switching;
- the driver remains command-ready during managed-runtime degradation while
  public tenant traffic remains on maintenance;
- unrelated tenant reconciliation continues while another tenant waits for a
  long health check, proving that no global lock is held;
- secret values are absent from Quadlets, generated systemd units, environment
  inspection, journals and release records, and PostgreSQL contains no unkeyed
  secret-value digest;
- complete recovery, erasure replay, privacy export and backup rehearsal pass
  without a mounted runtime API socket;
- a real Debian 13 and Podman 5.x VM passes Quadlet generation,
  `systemd-analyze --user verify`, reboot and failure-injection tests.

## 16. Pull-request order

1. `mb-control-plane`: extend authoritative domain records, add the normalized
   intent view and persist non-secret runtime specifications.
2. `mb-control-plane`: add Docker dynamic restart policies.
3. `mb-control-plane`: add boot and periodic reconciliation.
4. `mb-control-plane`: add readiness and live Docker reboot tests.
5. `mb-control-plane`: freeze driver contract fixtures and normalized runtime
   observations.
6. `mb-control-plane`: extract runtime interfaces behind the unchanged Docker
   backend.
7. `mb-infra`: implement the Quadlet agent, crash-safe journal, typed renderer,
   immutable artifact installation and current/previous protocol tests.
8. Both repositories: add the agent client and cross-repository conformance
   workflow.
9. `mb-infra`: migrate Paperless dynamic resources.
10. Both repositories: migrate transient jobs and recovery tests.
11. Both repositories: migrate Odoo slots and gateway reload.
12. `mb-infra`: install the agent through Ansible, enforce active/retained
    release grants, add the runtime traffic gate and monitoring.
13. Staging: run reboot, interruption, isolation, recovery and rollback
    qualification and retain evidence.
14. Both repositories: reject production compatibility-socket operation and
    remove obsolete Podman configuration.

## 17. References

- Podman Quadlet and rootless search paths:
  <https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html>
- Podman Quadlet management:
  <https://docs.podman.io/en/latest/markdown/podman-quadlet.1.html>
- Docker restart policies:
  <https://docs.docker.com/engine/containers/start-containers-automatically/>
