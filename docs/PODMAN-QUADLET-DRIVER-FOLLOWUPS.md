# Podman/Quadlet driver optional follow-ups

Status: deferred until the core driver migration is qualified

Core plan: `docs/PODMAN-QUADLET-DRIVER-PLAN.md`

## 1. Purpose and sequencing

This document contains useful capabilities that are not required to remove the
production Podman compatibility socket or obtain reliable reboot behavior.

Do not place these items on the critical path unless a concrete production
requirement appears. Each follow-up should have its own approval, threat model,
acceptance tests and release boundary.

Recommended order:

1. bounded operator log tail;
2. live log streaming only if tail is insufficient;
3. longer-term centralized logging if retention/search is required;
4. deleted-resource/host-replacement reconstruction improvements;
5. historical runtime observations if operators need them;
6. event-driven drift reconciliation if measured recovery time requires it;
7. a separate host agent only if a reviewed threat model rejects the native
   driver boundary;
8. generic placement or multi-cluster orchestration only after a second real
   runtime cluster exists.

## 2. Bounded operator log tail

Start with a finite tail rather than a live stream.

### 2.1 Backend behavior

- Docker development reads the Engine container-log endpoint without `follow`.
- Quadlet production reads one exact user-systemd unit from journald.
- The caller supplies an opaque resource key, never a container ID, unit name,
  journal match, path or command.

Example resource keys:

```text
workshop/<uuid>/paperless
runtime/shared-odoo/blue
service/control-api
job/<action-id>
```

The backend maps the key to a deterministic resource already known to the
driver.

### 2.2 Authorization and privacy

Add a dedicated `runtime.logs.read` permission through reviewed platform roles
and require recent strong authentication. Workshop resources additionally
require workshop authority unless an explicitly audited platform security role
is used.

Audit only:

- actor;
- resource key;
- requested cursor/time range;
- record and byte count;
- completion status.

Never store message contents in control PostgreSQL, audit payloads, traces or
driver operation responses.

### 2.3 Limits

Initial hard limits:

- default 200 records;
- maximum 1,000 records;
- maximum 16 KiB per message;
- maximum 2 MiB per response;
- maximum two concurrent requests per operator;
- strip terminal control sequences and replace invalid UTF-8.

Every service remains responsible for producing secret-safe and
privacy-minimized logs. Response redaction is defense in depth, not the primary
secret boundary. Exclude resource classes whose output cannot satisfy this
contract.

### 2.4 Acceptance

- arbitrary container/unit names and journal matches are rejected;
- unauthorized workshop and stale-MFA requests are rejected;
- Docker and journald fixtures normalize to the same record schema;
- record and byte limits are enforced;
- secret canaries never appear in returned fixtures;
- log contents do not enter PostgreSQL, traces or audit payloads.

## 3. Live log streaming

Implement only after operators demonstrate that bounded tail is insufficient.

Use server-sent events because delivery is one-way. Extend the normalized record
with an opaque backend cursor:

```text
RuntimeLogRecord
  cursor
  timestamp
  resource_key
  stream        stdout | stderr | service
  message
  truncated
```

Additional limits:

- maximum duration 5 minutes;
- maximum 5 MiB transferred;
- bounded global stream count;
- immediate backend cancellation on browser/API disconnect;
- explicit terminal reasons such as `duration_limit`, `byte_limit`,
  `resource_stopped` and `backend_unavailable`;
- no runtime/reconciliation lock held for the stream lifetime.

Tests must prove disconnect cleanup for tasks, subprocesses, journal readers,
HTTP bodies and file descriptors.

## 4. Centralized log retention and search

Direct tail/stream access is not a retention system. If incident response needs
historical search, forward journald through a separately reviewed collector to
a dedicated logging backend.

That project requires independent decisions for:

- hosting region and processor terms;
- tenant and operator access boundaries;
- field allowlists and source-side redaction;
- retention and deletion;
- query audit;
- ingestion backpressure and disk buffering;
- cost and availability;
- incident export controls.

Do not write general application logs into control PostgreSQL.

## 5. Deleted-resource and host-replacement reconstruction

The core plan persists enough Paperless specification to generate its Quadlet
and already retains Odoo release-slot state. Add a more general reconstruction
catalogue only if host replacement cannot rebuild from those domain records and
protected secret backups.

Before adding a table, prove which exact fields are missing. Prefer narrow
extensions to `service_instances` and `runtime_release_slots` over a generic
resource document.

Requirements:

- desired state has one authoritative domain writer;
- specifications contain no secret values or unkeyed secret hashes;
- secret generation IDs trigger replacement without exposing verifier data;
- missing protected secret material fails closed;
- reconstruction never generates a replacement credential implicitly;
- host replacement qualification restores two isolated workshops and the
  active Odoo slot from reviewed backups.

## 6. Historical runtime observations

The core driver returns normalized observations and emits metrics. Add a durable
observation table only after an operator use case needs historical per-resource
evidence that metrics or the immutable operation response cannot provide.

If added:

- observations never become desired-state authority;
- one bounded row is stored per meaningful transition, not per polling cycle;
- retention is explicit;
- resource labels are privacy-minimized;
- raw logs, commands, environment and secret-derived digests are prohibited.

## 7. Event-driven drift reconciliation

The core uses startup reconciliation, operation postconditions and the existing
durable periodic tenant reconciliation.

Add a runtime event watcher only if measured mean time to repair is inadequate.
It should trigger a normal idempotent reconciliation operation rather than
mutating resources from a second scheduler.

Possible triggers:

- Docker daemon reconnect in development;
- systemd unit failure;
- Podman health transition;
- gateway reload failure;
- missing dynamic Quadlet generation.

Use per-resource coalescing and rate limits to prevent failure loops.

## 8. Optional separate host agent

The core plan deliberately uses a native rootless driver. Introduce a separate
host agent only if a reviewed threat model concludes that systemd sandboxing and
the `tenant-runtime` boundary are insufficient because application-level driver
logic must not hold direct user-systemd/Podman authority.

That decision must identify the concrete attack it mitigates and compare it
against the additional failure modes introduced by another service.

If approved, the minimum agent design is:

- one mode-`0660` Unix socket using the core driver's dedicated client group;
- closed typed operations, no arbitrary unit text/command/path;
- deterministic resource names;
- same platform release and rollback set as the control driver;
- idempotent inspect-before-apply behavior;
- no desired-state authority;
- no second journal unless interruption tests prove inspection cannot reconcile
  ambiguous host effects.

Only if a second journal becomes necessary should the protocol add stable
action IDs, request digests, fsync-before-effect/success rules and N/N-1 protocol
compatibility. Do not implement that machinery speculatively.

## 9. Multi-cluster placement

Do not generalize the backend into a scheduler. The current system has one
rootless application runtime account and one shared Odoo runtime key.

Revisit placement only when a second real cluster or shard exists. At that
point, document:

- placement authority;
- resource ownership and fencing;
- cross-cluster release grants;
- network and secret boundaries;
- failover versus migration semantics;
- backup locality and recovery;
- operational ownership.

Until then, deterministic local resource names and one `RuntimeBackend` are the
intended design.
