# MakersBrain control-plane roadmap

Status: active

This roadmap is the single record of incomplete control-plane work: capability
status, the rules that constrain how it is finished, the release gates, and the
governance decisions that block production. The system that exists today is
described only by `CONTROL-PLANE-ARCHITECTURE.md`.

Delivery phases 0 to 4 -- documentation and characterization, command and secret
safety, Odoo release adoption, product capability correction, and modularization
with typed contracts -- are delivered; their implementation specifications were
retired with the improvement plan and the resulting system is described in the
architecture document. The remaining phase is below.

## Capability status

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
| Typed OpenAPI and generated web client | Implemented and verified | One route-owned registration constructs Axum and OpenAPI. Typed request bodies, query/header and ETag semantics, executable success statuses, closed command/replay/in-progress response schemas, binary response media, and generated browser freshness are enforced. The bridge integration lane verifies the current client against the current external Odoo provider. |
| Worker/release/backup observability | Implemented with named limitation | Heartbeats, queue/release/recovery/HTTP/provider metrics, Odoo/Paperless/Rauthy availability, alerts, views, runbooks and privacy-minimised OTLP spans with durable W3C parent propagation exist; retained production alert-routing evidence remains P1. |
| Separate operator identity and step-up | Implemented with named limitation | Stable database roles and recent MFA/WebAuthn step-up exist; the separately registered production operator OIDC client remains P2 infrastructure work. |
| GDPR inventory, retention and rights workflows | Implemented with named limitation | Personal mode is fail-closed at the mandatory pre-migration dependency of every active processor; the field inventory, Article 30 processing-record draft, retention, DSR, holds, processor evidence, incidents, protected tombstones, automatic Odoo/Paperless restore replay, and encrypted seven-day single-use exports now aggregate allowlisted Odoo records/attachments plus Paperless OCR metadata and originals without storing processor bodies in control PostgreSQL. Formal controller approval, approved production regions/processors, additional live processor adapters and retained full-topology evidence remain P0/P2. |
| Podman/systemd production driver | Planned in `mb-infra` | P2 before paid production. |
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
gate below pass. Calendar dates do not replace those gates.

## Principles and non-negotiable rules

1. **Desired state is recorded before external mutation.** APIs validate,
   authorize and enqueue. Workers or deployment jobs perform external changes.
2. **Observe before create or retry.** An unknown provider outcome is reconciled
   before another create is attempted.
3. **One release identity means one immutable artifact set.** Mutable tags and
   process package versions are not release identities.
4. **No shared-runtime swap before database compatibility is proven.** A failed
   tenant upgrade blocks that release or leaves the tenant on a compatible
   runtime pool.
5. **No destructive compensation.** A failed provisioning or release operation
   does not delete a working database, filestore or document archive.
6. **Secrets are capabilities.** A process receives only the capabilities its
   current queue needs.
7. **Product capabilities are stable; Odoo module lists are internal.** Users
   enable workshop features, not implementation packages.
8. **Recovery precedes destructive or schema-changing work.** A verified
   recovery point is a gate, not a best-effort side effect.
9. **Contracts are generated or validated from one source.** Environment
   requirements, routes, schemas and capability dependencies must not drift
   between Rust, Compose, JSON and documentation.
10. **Do not generalize before a second real consumer.** Multi-shard placement,
    custom domains and a generic workflow engine remain deferred.
11. **Privacy is enforced by design and by default.** Personal data is
    collected only for a documented purpose, retained for a bounded period,
    excluded from telemetry by default and accessible only to roles that need
    it. GDPR evidence is part of the release contract, not a policy document
    detached from implementation.

### Scope exclusions

The control-plane programme does not change, redesign or deploy:

- `mb_catalogue_sync`;
- the sibling catalogue scraper or its webservice;
- Decodo proxy pools, credentials, regional routing or sticky sessions;
- supplier-site acquisition, scraping policy or catalogue normalization.

Those systems may continue to integrate through their existing contracts, but
their internals and operations are outside this control-plane improvement
programme. Control-plane work must not create a dependency on their source,
configuration or proxy credentials.

## Priority and release gates

### Gate P0 — required before non-synthetic data

- tenant Odoo release manifest and adoption workflow;
- per-process database roles and secret sets;
- invitation capability redesign;
- complete startup configuration validation;
- consistent idempotency and optimistic concurrency;
- database-enforced audit immutability for application roles;
- GDPR data inventory, retention jobs, data-subject request workflow and
  privacy-safe telemetry defaults;
- negative tenant-isolation and secret-leak tests.

### Gate P1 — required before a second live workshop

- capability registry redesign and `mb_ceramics_workflow` activation path;
- API, worker and driver modularization;
- typed OpenAPI and generated web client;
- release, queue, backup and drift metrics;
- canary and full-fleet Odoo release rehearsal;
- operator runbooks for failed upgrade, failed restore and credential rotation.

### Gate P2 — required before paid production

- staging deployment through the infrastructure release contract;
- operator identity separated from an email allowlist;
- step-up authentication for destructive platform actions;
- production object-lock, PITR and quarterly disaster-recovery evidence;
- load, provider-outage and worker-termination tests;
- signed release provenance, SBOM retention and previous-image availability.

## Remaining delivery phase — operations and production rehearsal

1. Add heartbeats, metrics, tracing and alert rules.
2. Add platform roles and step-up operator actions.
3. Deploy through staging infrastructure identities and Podman driver.
4. Run full isolation, failure and recovery tests.
5. Rehearse class A/B rollback and class C recovery.
6. Exercise data-subject requests, retention, backup erasure replay and breach
   response; retain the reviewed DPIA and processing records.

Gate: retained evidence satisfies every acceptance criterion below.

## Final acceptance criteria

The programme is complete when:

- a signed immutable release can upgrade and verify all tenant databases
  without shell access;
- replacing the shared Odoo runtime is impossible until every routed tenant is
  compatible;
- every tenant records its exact image digest, source commit and addon versions;
- a failed tenant upgrade leaves other tenants available and prevents unsafe
  activation;
- each worker has a distinct database role and only its documented secrets;
- no plaintext invitation capability exists in PostgreSQL, logs or operation
  payloads;
- every mutating API operation has correct identical replay, payload-mismatch
  rejection and stale-write behavior;
- audit rows are immutable to application runtime roles;
- `mb_ceramics_workflow` and other workshop capabilities have complete,
  entitlement-aware activation paths;
- the OpenAPI document and web client are generated from typed contracts;
- no provider network call holds an open database transaction;
- queue age, worker freshness, release drift, backup freshness and restore
  rehearsal status are observable and alerted;
- two-workshop negative isolation tests pass for Odoo, Paperless, Redis,
  secrets, backups and routes;
- production deployment uses the infrastructure driver rather than a mounted
  Docker socket;
- recovery and rollback exercises have retained evidence and named owners;
- the personal-data inventory covers every schema/API/event/telemetry field;
  controller-approved retention and erasure jobs run with evidence;
- access, rectification, restriction, portability and erasure workflows pass
  tenant-isolation tests, including erasure replay after backup restore;
- production has reviewed processing records, processor/transfer safeguards,
  a DPIA and a rehearsed 72-hour breach-decision workflow.

## Explicit non-goals

Do not include these without a new trigger:

- Kubernetes;
- a generic BPM/workflow engine;
- event sourcing or CQRS for control-plane state;
- automatic Odoo module uninstall;
- custom tenant domains before a real customer requires one;
- multiple runtime clusters before a second shard is operated;
- any change to catalogue sync, the scraper webservice, Decodo configuration or
  proxy policy;
- storing invoice/document bodies in control PostgreSQL;
- replacing Rauthy, Odoo or Paperless functionality already owned by those
  systems.

## Decisions required before gated production

Known interim governance state:

- the project owner is the initial technical platform administrator;
- no legal entity/data controller has been designated yet;
- no DPO has been appointed yet;
- Paris is the preferred processing region and Azure West Europe is the EEA
  fallback;
- production processing of customer personal data is blocked until the
  controller and applicable processor agreements are formally recorded.

The implementation fails closed without these decisions. They are still
required before their corresponding production gate can be approved:

1. Which product plans permit each capability? The entitlement path is shipped
   and requires an explicit per-workshop capability list, but the commercial
   authority still has to approve the plan-to-capability matrix before live
   entitlements are issued.
2. Which legal entity will become the GDPR controller, whether appointment of a
   DPO is required or chosen, which lawful basis applies to each processing
   purpose, and which retention periods receive legal approval.
3. Which Paris/West Europe providers and subprocessors are approved under
   Article 28 processor terms?
