# MakersBrain control-plane roadmap

Status: active
Source of implementation order: `CONTROL-PLANE-IMPROVEMENT-PLAN.md`

This roadmap records the status of incomplete control-plane capabilities. The
current system is described only by `CONTROL-PLANE-ARCHITECTURE.md`.

| Capability | Status | Gate or limitation |
| --- | --- | --- |
| Durable queued external operations | Implemented with a named evidence gap | Central retry/safety classification and critical Rauthy, Odoo and Paperless adapter outcomes are unit-tested; full-topology provider termination and unknown-outcome injection remain a Phase 5 gate. |
| Exact-host Odoo tenant routing | Implemented and verified | Exact-host/header replacement, opaque database selection and distinct per-workshop bridge credentials with tenant-database verifiers are implemented; a retained negative full-topology suite must become a production gate. |
| Opaque database-per-workshop isolation | Implemented and verified | Full-topology negative rehearsal remains a production evidence gate. |
| Odoo/Paperless paired recovery | Implemented with limitation | Pre-erasure restores remain in maintenance until encrypted tombstone lookup and Odoo/Paperless replay evidence complete; production object lock/PITR and a retained full-topology replay rehearsal remain P2, against the acceptance criteria below. |
| Tenant Odoo release adoption | Implemented with named limitation | Signed manifests, state machines, fleet fencing, per-tenant recovery, activation intent and operator flows exist; two-image canary/failure rehearsals and production driver evidence remain P1/P2. |
| Per-process database roles/secrets | Implemented with named limitation | Local role grants, exact environment ownership, mounted secret-file references, fail-fast resolution, rendered-Compose canaries, separately mounted Odoo/Paperless integration-token volumes, driver-only versioned long-lived subpaths and UUID-scoped short-job mounts are present. A live Docker canary proves read-only subpath isolation; production secret-manager issuance and retained infrastructure-driver process evidence remain P0. |
| Invitation capabilities outside PostgreSQL/logs | Implemented and verified | Ed25519 rotation, generation invalidation, database migration and no-plaintext checks pass. |
| Central command replay and ETags | Implemented and verified | Every persistent authenticated public mutation, including identity linking, uses centralized RFC 8785 admission and stored replay; versioned resources additionally use strong ETag compare-and-set. Non-persisting validation and single-use artifact retrieval are the only documented header exceptions. |
| Database-enforced immutable audit | Implemented and verified | Trigger, grants and runtime role-matrix tests pass. |
| Rust responsibility split | Implemented and verified | API contracts, governance, platform/release, workshop authority, recovery, internal integrations and route ownership; email/privacy/release/lifecycle/extraction workers; and driver privacy, release, recovery, gateway, tenant-service, raw Docker Engine and PostgreSQL responsibilities are separated behind private module boundaries. Composition roots retain shared admission, configuration and narrow cross-domain primitives. |
| Versioned product capability registry | Implemented and verified | V1 is materialized without a hard-coded key check; activation pins registry/release/entitlement/implementation evidence. Periodic reconciliation immediately gates drift, Odoo capability-owned writes and Paperless mutations, while retaining historical reads; `restricted` requires downstream evidence. |
| Typed OpenAPI and generated web client | Implemented and verified | One route-owned registration constructs Axum and OpenAPI. Typed request bodies, query/header and ETag semantics, closed command/replay/in-progress response schemas, binary response media, generated browser types and v1 compatibility comparison are enforced. Bodyless legacy 2xx entries remain only as v1 compatibility placeholders and advertise no representation. |
| Worker/release/backup observability | Implemented with named limitation | Heartbeats, queue/release/recovery/HTTP/provider metrics, Odoo/Paperless/Rauthy availability, alerts, views, runbooks and privacy-minimised OTLP spans with durable W3C parent propagation exist; retained production alert-routing evidence remains P1. |
| Separate operator identity and step-up | Implemented with named limitation | Stable database roles and recent MFA/WebAuthn step-up exist; the separately registered production operator OIDC client remains P2 infrastructure work. |
| GDPR inventory, retention and rights workflows | Implemented with named limitation | Personal mode is fail-closed at the mandatory pre-migration dependency of every active processor; the field inventory, Article 30 processing-record draft, retention, DSR, holds, processor evidence, incidents, protected tombstones, automatic Odoo/Paperless restore replay, and encrypted seven-day single-use exports now aggregate allowlisted Odoo records/attachments plus Paperless OCR metadata and originals without storing processor bodies in control PostgreSQL. Formal controller approval, approved production regions/processors, additional live processor adapters and retained full-topology evidence remain P0/P2. |
| Podman/systemd production driver | Planned in `makersbrain-infra` | P2 before paid production. |
| Multiple runtime clusters | Deliberately deferred | Trigger: operation of a second real shard. |
| Custom tenant domains | Deliberately deferred | Trigger: a contracted customer requirement. |
| Generic workflow engine | Deliberately deferred | Trigger: a second real workflow consumer not expressible by current operations. |

## P2 recovery rehearsal acceptance criteria

The backup and restore implementation is delivered; these criteria are what the
outstanding full-topology rehearsal must demonstrate before scheduled backups
are enabled in production. Rehearse with `documents` both off and on, under
active invoice ingestion, and against corrupt or truncated objects, wrong keys,
expired credentials, worker crashes, scope mismatches and rollback failures.

- A workshop without Paperless produces and restores an Odoo-only recovery set.
- A workshop with Paperless restores Odoo, all documents, metadata, unconsumed
  files and stable document IDs from one recovery point.
- No recovery point reaches `ready` without complete remote verification.
- A partial, modified or wrongly encrypted object cannot be restored.
- Restore failure leaves the original workshop recoverable and closed to users
  until rollback or operator intervention succeeds.
- Backup-writer credentials cannot delete immutable production backups.
- No plaintext document, database dump, S3 credential or private restore key is
  exposed through the API, operation payloads or logs.

Progress is accepted only when the tests and evidence named by the corresponding
gate in `CONTROL-PLANE-IMPROVEMENT-PLAN.md` pass. Calendar dates do not replace
those gates.
