# Podman/Quadlet deployment-driver plan

Status: proposed, core delivery scope

Related optional work:
`docs/PODMAN-QUADLET-DRIVER-FOLLOWUPS.md`

Repositories:

- `mb-control-plane`: driver contract, durable operations, runtime backend and
  Docker development implementation;
- `mb-infra`: production host identity, systemd units, Quadlet layout, release
  grants and deployment qualification.

## 1. Objective

Move staging and production dynamic workloads from raw Podman compatibility-API
containers to rootless Podman Quadlets managed by user systemd.

The migration must first fix the existing Docker reboot gap, preserve the
current authenticated and idempotent HTTP driver contract, and avoid building a
second orchestration service.

The completed core plan provides:

- Docker as a development-only backend;
- a native rootless production driver managed by `mb-infra`;
- no Docker or Podman API socket in staging or production;
- Docker reboot recovery for dynamic Paperless and active Odoo containers;
- persistent Paperless and Odoo Quadlets that survive reboot;
- one-shot jobs that never restart automatically;
- a fail-closed tenant gateway during boot and runtime switching;
- active and previous release support for bounded rollback;
- one PostgreSQL driver operation ledger, not a second host journal;
- common contract and failure tests across Docker and Quadlet.

Live log streaming, centralized log retention, a generic observation history,
multi-cluster placement and a separate host agent are deliberately outside the
critical migration. They are described in the follow-up plan.

## 2. Current state and concrete gaps

`control-container-driver` and `control-docker-driver` currently run the same
Rust implementation. `DRIVER_CONTAINER_RUNTIME` changes only the
Docker-compatible API version and socket.

### 2.1 Docker reboot gap

Static Compose services use `restart: unless-stopped`. Dynamic Paperless and
Odoo blue/green containers are created without a restart policy, so Docker uses
its default `no` policy. After a host or Docker daemon restart:

- volumes and protected secret files remain;
- the driver and static Compose services restart;
- dynamic Paperless and release-specific Odoo containers remain stopped;
- driver startup repairs database limits and maintenance routes but does not
  restore the complete dynamic runtime.

### 2.2 Production ownership gap

`mb-infra` renders static Quadlets but runs `control-container-driver` in a
container with the rootless Podman API socket. The driver creates long-running
tenant resources outside Quadlet/systemd ownership.

`mb-infra` also renders static `odoo.service`, while the release driver creates
`mb-odoo-blue` and `mb-odoo-green`. The migration must establish one owner for
the shared Odoo runtime slots.

## 3. Target architecture

```text
control API and workers
        |
        | authenticated HTTP over a protected Unix socket
        v
control-container-driver
native tenant-runtime user service
        |
        +-- DockerBackend in development only
        |
        +-- QuadletBackend in staging/production
                |
                +-- atomic dynamic Quadlet files
                +-- systemctl --user lifecycle
                +-- typed podman/systemd one-shot jobs
                +-- gateway route validation/reload
```

There is no separate Quadlet agent or second action journal. `mb-infra` owns how
the production driver binary is installed, sandboxed, configured and rolled
back. `mb-control-plane` owns the binary and its behavior.

### 3.1 Production connectivity

The native driver uses a systemd socket unit below the `tenant-runtime` runtime
directory. The socket is mode `0660`, owned by `tenant-runtime` and one dedicated
driver-client group. Only API, worker and scheduler Quadlets that need the
existing driver contract receive that supplemental group and mount the exact
socket. The Podman user/group mapping must preserve the supplemental group and
is qualified with the production Quadlets. No other service receives the group.

Existing bearer credentials remain required; socket membership is an additional
boundary, not a replacement for authentication.

The control-plane HTTP client must support both:

- TCP URLs for local Docker development;
- HTTP over the configured Unix socket for staging and production.

The native driver needs bounded access to existing internal services:

- PostgreSQL remains certificate-validated through its configured address;
- Redis exposes a host Unix socket owned only by `tenant-runtime` for ACL
  administration while retaining its private container-network TCP listener;
- Rauthy and the internal control API expose authenticated loopback-only host
  ports, or an equivalent protected Unix transport where supported;
- Odoo candidate smoke checks use fixed loopback-only slot ports or a typed
  `podman exec`/probe job that does not place credentials in argv.

No internal administration endpoint may bind a public address. Every HTTP
endpoint retains its existing scoped authentication.

### 3.2 Native service sandbox

`mb-infra` installs the driver as a `tenant-runtime` user service with:

- `NoNewPrivileges=yes`;
- an explicit systemd credential set;
- a read-only system filesystem except for exact dynamic Quadlet, route,
  backup, tenant-secret and state paths;
- a private temporary directory;
- a bounded process/file-descriptor limit;
- restricted address families and system calls compatible with PostgreSQL,
  HTTP, Unix sockets, systemd and rootless Podman;
- no login shell or host-root authority;
- journald rate limits and secret-safe logging.

The service has the same rootless Podman-user authority that the current socket
mount provides, but no container-runtime daemon socket and no extra RPC layer.

## 4. Phase 1: repair Docker reboot behavior

This is the first implementation milestone and can ship independently.

### 4.1 Explicit restart policies

Update dynamic Docker create requests:

| Resource | Restart policy |
| --- | --- |
| Enabled Paperless service | `unless-stopped` |
| Active Odoo slot | `unless-stopped` |
| Candidate Odoo slot | `no` |
| Retained, inactive or failed Odoo slot | `no` |
| Migration, initialization, backup and restore job | `no` |

Add a backend operation to update the restart policy of an existing container.
During an Odoo activation, set the candidate to `unless-stopped` before opening
tenant traffic and set the retained slot to `no` before deliberately stopping
it.

### 4.2 Startup reconciliation

Add one bounded startup pass after the current database-limit repair. Fold the
existing maintenance-route recovery into the final validated route
reconstruction; it must not reopen a saved route before runtime health is
known:

1. read the active slot and any non-terminal release operation;
2. ensure the active slot is running with `unless-stopped`;
3. ensure retained, inactive and failed slots use `no` and remain stopped;
4. leave `starting`, `verifying` and `prepared` candidates to the durable release
   operation: startup neither resumes nor stops them and keeps tenant traffic on
   maintenance until that operation reconciles its postcondition;
5. find Paperless service instances expected to run and start their existing
   matching containers;
6. verify configuration labels before starting anything;
7. leave unknown containers untouched and report them;
8. validate the gateway route digest;
9. open tenant routes only after the active runtime is observed healthy and no
   release operation still owns a candidate transition.

The first Docker fix does not need a generic runtime-intent table or complete
missing-container reconstruction. A reboot does not delete containers. Existing
periodic durable tenant reconciliation remains the drift-repair mechanism.

If a known container is missing, startup reports degraded state and leaves
tenant traffic on maintenance. Reconstructing a deleted resource is added only
when the Quadlet desired-state representation exists.

### 4.3 Readiness and traffic safety

`/health/live` remains process-only. `/health/ready` means the driver can accept,
journal and execute repair commands. A degraded managed resource does not make
the driver unavailable.

Before the gateway binds its tenant listener, one small prerequisite service
removes every generated tenant `*.conf` from the gateway include directory and
installs one validated default maintenance response. All removed routes are
derivable from control-plane state. The gateway depends on that prerequisite;
the driver still depends on the gateway. The prerequisite has no database
access, journal or reconciliation logic and never reconstructs routes.

Startup reconciliation atomically installs active tenant routes only after the
recorded slot, image/configuration labels, health and route digest agree.
Operator, API and authentication routes remain reachable for repair.

### 4.4 Docker tests

Tests must prove:

- dynamic create requests contain the correct restart policy;
- one-shot jobs never restart;
- the active Odoo slot returns after Docker restart;
- retained and inactive slots remain stopped;
- existing Paperless containers return after Docker restart;
- restart-policy drift is repaired;
- two active slots or another ambiguous state fail closed;
- an interrupted `starting`, `verifying` or `prepared` candidate is not changed
  by startup and remains fenced until its release operation reconciles;
- unknown containers are reported but not deleted;
- the gateway cannot expose a persisted active route before its pre-start
  maintenance prerequisite completes;
- an interrupted lifecycle route backup cannot reopen traffic before runtime
  validation;
- the driver remains command-ready while tenant routes remain on maintenance;
- repeated startup reconciliation is idempotent.

Add one live Docker test that provisions two Paperless workshops, activates one
Odoo slot, restarts Docker and verifies restart, routing and isolation.

## 5. Phase 2: introduce one runtime backend boundary

Use one internal `RuntimeBackend` trait or enum. Do not split it into a family of
interfaces until a concrete implementation needs that separation.

The initial typed operations are:

```text
inspect(resource_key)
ensure_paperless(desired)
ensure_odoo_slot(desired)
set_state(resource_key, running|stopped|absent)
ensure_volume(desired)
run_job(job_kind, bounded_parameters, secret_paths)
reload_gateway(expected_digest)
```

Return one normalized observation:

```text
RuntimeObservation
  resource_key
  desired_digest
  observed_digest
  image_digest
  state
  health
  runtime_object_id
```

The observation is returned to the caller and used for metrics/evidence. Do not
add a generic observation-history table in the core migration.

Implementations:

- `DockerBackend`: wraps the current Engine API transport;
- `QuadletBackend`: writes validated Quadlets and invokes bounded user-systemd
  and Podman commands.

Configuration changes:

- add `DRIVER_BACKEND=docker|quadlet`;
- keep `DRIVER_RUNTIME_SOCKET` only for Docker development;
- add `DRIVER_QUADLET_ROOT`, `DRIVER_SYSTEMD_RUNTIME_DIR` and the protected
  driver Unix-listener path;
- reject `DRIVER_BACKEND=docker` outside development;
- update configuration spec, release contract, secret staging and agreement
  tests together.

## 6. Phase 3: deploy the native production driver

### 6.1 Immutable artifact

The control-plane release publishes the native driver binary as a digest-pinned
OCI artifact in addition to the control container image. `mb-infra` verifies the
same release provenance already required for the control image.

Install under a versioned path:

```text
/opt/makersbrain/control-container-driver/<artifact-digest>/
```

An atomic symlink selects the active binary. Retain the immediately previous
binary for the platform rollback window.

### 6.2 Credentials and configuration

Use systemd `LoadCredential=` or exact mode-`0400`/`0600` files prepared by the
existing Infisical materialization path. The native service receives only the
credentials currently scoped to the driver.

Do not place secret values in:

- the unit file;
- environment values;
- Quadlet source;
- Podman/systemd command argv;
- release records;
- journald messages.

Configuration may use `@/run/credentials/...` references resolved by the
existing runtime-secret boundary.

### 6.3 Activation and rollback

`mb-infra` installs and validates the candidate binary before switching the
static application release. Activation checks:

- binary digest and provenance;
- configuration contract version;
- database schema epoch compatibility;
- rootless Podman and user-systemd access;
- writable-path confinement;
- Unix socket ownership, supplemental-group mapping and authorized client access;
- no-mutation backend preflight.

On failure, restore the previous binary symlink and service unit before
restoring the previous static release.

## 7. Phase 4: dynamic Quadlet resources

### 7.1 Storage layout

Keep static and dynamic Quadlets separate:

```text
~/.config/containers/systemd/
  makersbrain -> immutable static platform release
  makersbrain-dynamic/
    paperless/
    odoo-slots/
    volumes/
```

For every persistent mutation, the driver:

1. validates a typed desired resource;
2. renders into a temporary directory;
3. verifies the exact candidate with the Quadlet generator;
4. atomically selects the resource generation;
5. runs `systemctl --user daemon-reload`;
6. starts/reloads/stops the derived service;
7. waits for bounded health;
8. returns the normalized observation.

The driver accepts no arbitrary unit text, unit name, host path, command or
environment key from an HTTP caller.

Removing a Quadlet file does not delete data. The driver stops the service,
removes the selected unit generation and reloads systemd. Volume deletion is a
separate retention-gated operation.

### 7.2 Paperless

Persist only the non-secret Paperless fields that cannot be derived from
existing `service_instances`, workshop state and deterministic naming. A narrow
closed `runtime_spec` on the Paperless service row is acceptable; do not create
a generic resource catalogue.

The generated unit includes:

- exact image digest;
- deterministic service/container and volume names;
- fixed rootless network;
- database and Redis identity names;
- read-only versioned secret directory;
- explicit writable mounts/tmpfs;
- dropped capabilities and read-only root filesystem where supported;
- health and restart policy;
- a digest of non-secret configuration and secret generation IDs.

No unkeyed hash of a secret value is stored in PostgreSQL.

### 7.3 Odoo slots

Remove static `odoo.container` after the dynamic slot path is qualified.
`control.runtime_release_slots` remains authoritative.

Map slot state as follows:

| Slot state | Runtime state |
| --- | --- |
| `active` | running and boot-selected |
| `starting`, `verifying`, `prepared` | explicitly started only by its operation |
| `retained`, `inactive`, `failed` | stopped |

The Odoo data volume remains infrastructure-defined. The gateway selects only
the active slot after health and route validation.

### 7.4 One-shot jobs

Do not generate persistent Quadlets for every transient job. Use a typed,
bounded command such as `systemd-run --user --wait --collect` around
`podman run --rm`.

Each job kind owns an exact image allowlist, command template, scalar parameter
schema, mount list, timeout, output limit and retry classification. Job secrets
are exact regular files below the job-secret root and are removed only after
the job is terminal and absent.

Restore, erasure, database cutover and credential rotation are never blindly
replayed. On an ambiguous disconnect, the existing driver operation remains
`in_progress`. A retry first inspects the deterministic systemd scope or
external postcondition and never repeats the effect blindly.

## 8. Idempotency and reconciliation

Keep `control.deployment_driver_operations` as the single operation ledger.
Every runtime resource and job has a deterministic name derived from validated
domain identifiers and action IDs.

Before mutation, the driver:

1. durably admits the idempotency key and request digest;
2. inspects the deterministic existing resource;
3. returns the prior result when desired and observed digests already match;
4. applies one bounded mutation otherwise;
5. observes the postcondition;
6. commits success only after the postcondition is durable.

An ambiguous runtime/systemd outcome remains reconcilable. The driver never
changes it to an ordinary retryable failure without proving that no effect
occurred or that rollback completed.

Use per-resource locks. A fleet-wide lock is used only for Odoo route/slot
activation. Never hold a global lock while waiting for unrelated resource
health.

## 9. Release grants and rollback

The native driver may run only images admitted by the active or retained
previous composed platform release.

`mb-infra` materializes both records in a read-only grant directory. A grant
cannot be removed while referenced by:

- an active, prepared or retained Odoo slot;
- a non-terminal job;
- the supported application rollback;
- recovery tooling still within its retention window.

Online driver actions assert that an admitted digest is already present. Image
verification and pull remain deployment responsibilities.

Static rollback restores the matching previous binary, grant and static
Quadlet release as one set. Dynamic tenant units and volumes remain untouched;
the reconciler changes them only when their authoritative domain state requires
it.

## 10. Migration sequence

For each existing raw Podman Paperless or Odoo resource:

1. inventory image digest, mounts, volumes, labels and health;
2. render and verify the equivalent Quadlet;
3. place affected tenant traffic on maintenance;
4. stop and remove only the raw container object;
5. install/start the Quadlet using the same persistent volumes;
6. verify health, routing and secret isolation;
7. record success in the existing driver operation ledger;
8. reopen traffic.

Keep the raw Podman compatibility backend available in staging for one release
behind an explicit emergency flag. Never fall back automatically after a
partial Quadlet operation.

## 11. Verification gates

The core migration is complete only when:

- Docker and Quadlet pass the same driver contract fixtures;
- Docker reboot restores enabled Paperless and exactly the active Odoo slot;
- staging and production mount no container-runtime API socket;
- the native driver runs as `tenant-runtime` with verified filesystem and
  systemd confinement;
- authorized container users can reach the driver socket through the dedicated
  group, while otherwise identical containers without that group cannot;
- HTTP callers cannot supply unit names, commands, environment keys or host
  paths;
- two-workshop isolation passes for PostgreSQL, Redis, secrets, volumes,
  gateway routes, backups and restores;
- agent/second-journal components are absent from the deployed topology;
- driver termination at every activation boundary converges through the
  existing operation ledger and runtime inspection;
- unrelated tenant operations proceed while another resource waits for health;
- gateway boot and cutover never expose a stale or unhealthy tenant route;
- reboot restores persistent Quadlets and never restarts one-shot jobs;
- static rollback retains dynamic tenant resources and selects an admitted
  previous binary/image set;
- secret canaries are absent from units, Quadlets, argv, environment inspection,
  release records and journals;
- a real Debian 13/Podman 5.x VM passes generator verification, reboot,
  interruption, migration and rollback tests.

## 12. Pull-request order

1. `mb-control-plane`: Docker restart policies and startup reconciliation.
2. `mb-control-plane`: driver readiness, maintenance-route gating and live
   Docker reboot test.
3. `mb-control-plane`: one `RuntimeBackend` boundary with unchanged Docker
   behavior.
4. `mb-control-plane`: native driver Unix listener and digest-pinned binary
   artifact.
5. `mb-infra`: native user service, credentials, sandbox and protected internal
   connectivity.
6. Both repositories: Paperless Quadlet backend and migration tests.
7. Both repositories: typed one-shot job execution and recovery tests.
8. Both repositories: Odoo slot/gateway ownership migration.
9. `mb-infra`: active/previous grants, rollback integration and monitoring.
10. Staging: reboot, interruption, isolation, recovery and rollback
    qualification.
11. Both repositories: reject/remove production compatibility-socket operation.

## 13. References

- Podman Quadlet and rootless search paths:
  <https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html>
- Docker restart policies:
  <https://docs.docker.com/engine/containers/start-containers-automatically/>
