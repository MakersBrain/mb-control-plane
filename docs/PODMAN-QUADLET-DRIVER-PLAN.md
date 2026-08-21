# Podman/Quadlet deployment-driver plan

Status: proposed

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
| Command admission and control PostgreSQL ledger | `mb-control-plane` |
| Tenant provisioning, recovery and fleet release logic | `mb-control-plane` |
| Backend-neutral desired-state reconciler | `mb-control-plane` |
| Docker development backend | `mb-control-plane` |
| Versioned Quadlet-agent client | `mb-control-plane` |
| Host-agent service and Unix socket | `mb-infra` |
| Dynamic Quadlet templates and policy validation | `mb-infra` |
| Host action journal and systemd execution | `mb-infra` |
| Platform image/release execution grant | composed release in `mb-infra` |
| Staging and production qualification evidence | `mb-infra` |

## 4. Phase 0: Docker reboot safety and desired-state foundation

This is the first implementation milestone. It fixes an existing development
reboot gap and creates the semantic foundation for Quadlet.

### 4.1 Persist reconstructable runtime intent

Restart policies can restart an existing container but cannot recreate a
missing one. Persist one non-secret desired specification for every long-lived
dynamic resource.

Introduce a narrow runtime-intent catalogue, preferably a table such as:

```text
control.runtime_resource_intents
  resource_key         text primary key
  resource_kind        paperless | odoo-slot
  workshop_id          uuid nullable
  desired_state        running | stopped | absent
  specification        jsonb, closed and non-secret
  specification_digest sha256
  generation           bigint
  updated_at            timestamptz
```

The exact database name can change during implementation, but it must not
duplicate secret values or application authority.

For Paperless, persist:

- workshop ID;
- deterministic container and volume names;
- database name and database role;
- Redis username and key/channel prefix;
- public hostname;
- OIDC client ID;
- digest-pinned image reference outside development;
- expected secret paths and secret-boundary version;
- configuration digest;
- desired state.

Database passwords, Redis passwords, OIDC secrets, Django secrets, admin
passwords and bridge credentials remain only in protected tenant secret files.
The specification contains their expected paths and, where required, a digest,
never their values.

Odoo reconstruction should use existing application-release manifests,
`runtime_release_slots`, extension-volume records and protected release
configuration files. Persist only additional non-secret information required
to recreate an identical container.

The driver role receives permission to read desired intent and update bounded
runtime observations. It must not gain authority to change application-level
desired state.

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
3. atomically activate and verify gateway routes;
4. mark the new slot active in the durable control-plane state;
5. set the new active container to `unless-stopped`;
6. set the old container to `no`;
7. stop the old container when its retention state permits it.

The reconciler repairs restart-policy drift if the process terminates between
these steps.

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

If no active Odoo slot exists, readiness fails unless the database proves this
is a pristine installation with no provisioned workshop and no active
application release.

### 4.4 Add periodic reconciliation

Startup reconciliation alone does not handle a Docker daemon restart while the
driver process remains alive.

Add a background loop that:

- runs at a bounded 30-60 second interval;
- uses the existing mutation lock or a narrower per-resource lock;
- retries with exponential backoff while Docker is unavailable;
- reconciles immediately after the Docker socket reconnects;
- does not mutate a resource owned by an in-flight fleet, lifecycle or recovery
  action;
- records drift and repair metrics without secret values.

Every successful action should also reconcile and observe the affected
resource before returning.

### 4.5 Driver readiness

Keep `/health/live` process-only. Add or strengthen `/health/ready` so the
driver becomes ready only when:

- the driver ledger is reachable;
- PostgreSQL administration is reachable;
- the selected runtime backend is reachable;
- boot reconciliation completed;
- the recorded active Odoo slot is healthy, subject to the pristine-install
  exception;
- gateway configuration matches its durable intent;
- no unresolved activation intent makes runtime ownership ambiguous.

Change the Docker Compose driver health check from `/health/live` to
`/health/ready`.

### 4.6 Docker reboot tests

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
- gateway routes are restored before readiness;
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

## 11. Phase 7: migrate Odoo slots and gateway ownership

Remove the ownership conflict between `mb-infra`'s static `odoo.service` and
the driver's blue/green runtime containers.

Final ownership:

- remove static `odoo.container` from the persistent platform-unit set;
- let the driver own `mb-odoo-blue` and `mb-odoo-green` through the agent;
- keep the Odoo data volume infrastructure-defined and persistent;
- allow the gateway to start without requiring static `odoo.service`;
- route only to the recorded active slot;
- keep driver readiness false until a valid active slot exists, subject to the
  pristine-install exception.

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

Use the composed platform release as an execution grant:

- materialize the exact release record in an agent-readable, read-only path;
- admit only image digests present in that record;
- require the exact qualified Odoo runtime/extension pair;
- require release ID, runtime subject, extension subject and qualification
  digest agreement;
- pre-pull and verify images through `mb-infra` before granting them;
- make online driver operations assert local image presence instead of pulling
  an unreviewed image.

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

- install and start the agent socket before application Quadlet activation;
- create agent state and dynamic Quadlet directories with mode `0700`;
- verify lingering and the user systemd bus;
- remove Podman socket ordering and mounting from
  `control-container-driver.container`;
- set `DRIVER_BACKEND=quadlet-agent`;
- mount only the agent Unix socket into the driver;
- remove static Odoo ordering after slot migration;
- ensure `release.py` never removes the dynamic tree during static rollback;
- back up the agent journal and durable desired-state records, but not
  transient job units;
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
7. commit adoption evidence to both journals.

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
- reboot restores durable Paperless and the active Odoo slot but not abandoned
  one-shot jobs;
- static platform rollback leaves dynamic tenant units and volumes intact;
- blue/green activation survives failures before and after route switching;
- secret values are absent from Quadlets, generated systemd units, environment
  inspection, journals and release records;
- complete recovery, erasure replay, privacy export and backup rehearsal pass
  without a mounted runtime API socket;
- a real Debian 13 and Podman 5.x VM passes Quadlet generation,
  `systemd-analyze --user verify`, reboot and failure-injection tests.

## 16. Pull-request order

1. `mb-control-plane`: persist non-secret runtime intent.
2. `mb-control-plane`: add Docker dynamic restart policies.
3. `mb-control-plane`: add boot and periodic reconciliation.
4. `mb-control-plane`: add readiness and live Docker reboot tests.
5. `mb-control-plane`: freeze driver contract fixtures and normalized runtime
   observations.
6. `mb-control-plane`: extract runtime interfaces behind the unchanged Docker
   backend.
7. `mb-infra`: implement the Quadlet agent, journal, typed renderer and unit
   tests.
8. Both repositories: add the agent client and cross-repository conformance
   workflow.
9. `mb-infra`: migrate Paperless dynamic resources.
10. Both repositories: migrate transient jobs and recovery tests.
11. Both repositories: migrate Odoo slots and gateway reload.
12. `mb-infra`: install the agent through Ansible, enforce release grants and
    add monitoring.
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
