# MakersBrain control-plane improvement plan

Status: implementation baseline delivered; external production gates remain in
`CONTROL-PLANE-ROADMAP.md`
Scope: `control-plane/`, its Odoo integration, and its release contract with
`makersbrain-infra`
Supersedes: the incomplete delivery roadmap in `CONTROL-PLANE-DESIGN.md`; the
architectural boundaries in that document remain valid until they are moved to
the current-state architecture document described below.

## 1. Outcome

Turn the existing development control plane into a release-managed,
least-privilege platform that can safely operate multiple workshop databases on
one shared Odoo runtime.

The improved system must:

- adopt an Odoo addon release across tenant databases without manual commands;
- prove every tenant database is compatible before replacing the shared runtime;
- give each process only the database privileges and secrets it needs;
- keep plaintext invitation capabilities out of PostgreSQL;
- make every mutating API operation replay-safe and concurrency-safe;
- publish a typed, complete API and deployment contract;
- expose enough release, queue, drift and recovery evidence to operate the
  platform without shell access;
- present product capabilities to artisans instead of exposing implementation
  module names;
- preserve the existing strengths: durable operations, exact-host tenant
  routing, opaque database names, paired Odoo/Paperless recovery, provider
  isolation and human review of extracted accounting data.

This is an evolution of the current implementation, not a rewrite.

## 2. Current-state findings that drive the plan

### 2.1 The design document is no longer current

`CONTROL-PLANE-DESIGN.md` still describes a proposed extraction from
`../makersbrain`. The implementation now lives in this repository and already
contains:

- fourteen control-plane migrations;
- a real Docker deployment driver;
- tenant provisioning and reconciliation;
- membership, invitation and ownership flows;
- optional module activation;
- inventory and invoice extraction;
- paired Odoo/Paperless recovery sets;
- encrypted portable backups and restore rehearsals;
- an artisan UI and an operator UI.

The documentation must distinguish current architecture from future work.

### 2.2 Tenant Odoo release adoption is not modelled

The release contract describes the control database migration but does not
define how an Odoo image and its addon versions are adopted by every tenant
database. `service_instances.release_id` currently receives the Rust package
version from the Docker driver, which is not the Odoo image digest or addon
release.

This is unsafe with a shared runtime: the new Python code becomes active for all
databases when the container is replaced, while each database has its own
installed module set and migration history.

### 2.3 Runtime privileges are broader than the design promises

All workers inherit one control database credential, the Rauthy administration
credential, the deployment-driver credential, the mail credential and the
tenant secret volume. Queue isolation is currently a process topology, not a
security boundary.

### 2.4 Invitation plaintext enters the outbox

The invitation table stores a hash, but the outbox JSON stores the full
acceptance URL containing the plaintext token. That contradicts the documented
secret boundary and makes a database read sufficient to accept a pending
invitation.

### 2.5 Command admission is inconsistent

The shared operation store compares idempotent payloads correctly, but some API
handlers implement their own weaker behavior. ETags are advertised but not
enforced. Audit rows are described as append-only but the database does not
enforce that property for the application role.

### 2.6 Product capability and Odoo module boundaries have drifted

The control-plane capability registry omits `mb_ceramics_workflow`, does not express that kiln
connectivity requires firings, and does not check subscription entitlements
before activation. Technical Odoo modules are too granular for the artisan UX.

### 2.7 Composition files have outgrown their boundaries

`api.rs`, `worker.rs` and `docker_driver.rs` contain several independent
domains. Their size makes authorization, secret access, failure handling and
tests harder to review.

## 3. Principles and non-negotiable rules

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

### 3.1 Scope exclusions

This plan does not change, redesign or deploy:

- `mb_catalogue_sync`;
- the sibling catalogue scraper or its webservice;
- Decodo proxy pools, credentials, regional routing or sticky sessions;
- supplier-site acquisition, scraping policy or catalogue normalization.

Those systems may continue to integrate through their existing contracts, but
their internals and operations are outside this control-plane improvement
programme. Control-plane work must not create a dependency on their source,
configuration or proxy credentials.

## 4. Priority and release gates

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

## 5. Workstream A — make documentation authoritative

### A1. Split current state from roadmap

Create:

- `CONTROL-PLANE-ARCHITECTURE.md`: the system that exists now;
- `CONTROL-PLANE-ROADMAP.md`: incomplete work, decisions and gates;
- `CONTROL-PLANE-IMPROVEMENT-PLAN.md`: this implementation sequence;
- `control-plane/deploy/release-contract.json`: the machine-readable runtime
  contract.

After the new architecture document is accepted, replace
`CONTROL-PLANE-DESIGN.md` with a short historical note and links. Do not retain
two normative architecture descriptions.

### A2. Record implementation status per capability

For each capability, record one of:

- implemented and verified;
- implemented with a named limitation;
- planned in a named gate;
- deliberately deferred.

The architecture document must describe the actual source location, queue list,
service topology and recovery behavior. It must not refer to the abandoned
`../makersbrain` extraction layout.

### A3. Add architecture-decision records

Add concise ADRs for:

- shared Odoo runtime and database-per-workshop isolation;
- release adoption across tenant schemas;
- per-workshop Paperless processes with shared Redis ACLs;
- asymmetrically signed invitation capabilities and delivery redaction;
- Docker driver as development-only and Podman/systemd as production target;
- capability bundles versus Odoo modules.

### Acceptance

- No current-state statement conflicts with code or the release contract.
- Every deferred item has a trigger rather than a calendar promise.
- CI validates all documentation links and release-contract references.

## 6. Workstream B — tenant Odoo release management

This is the highest-priority engineering workstream.

### B1. Define the application release manifest

Publish a signed manifest containing:

```json
{
  "release_id": "odoo-2026.08.14-2cbc37c",
  "source_commit": "2cbc37c...",
  "odoo_version": "19.0",
  "image_digest": "sha256:...",
  "built_at": "...",
  "addons": {
    "mb_ceramics_firing": "19.0.3.0.0",
    "mb_ceramics_workflow": "19.0.3.0.0"
  },
  "oca": {
    "auth_oidc": "f51fe1b..."
  },
  "upgradeable_from": ["odoo-2026.07.30-..."],
  "database_runtime_compatibility": {
    "odoo-2026.07.30-...": "read-write"
  },
  "bridge_contract": ">=3.2.0,<4.0.0",
  "schema_epoch": 42,
  "change_class": "additive-compatible",
  "required_postconditions": ["registry_load", "xmlid_ownership", "health"]
}
```

The release ID must identify the Odoo artifact set. Do not use
`CARGO_PKG_VERSION`, an image tag, or a branch name.

Compatibility is directional and has separate meanings:

- `upgradeable_from` says which database release the candidate upgrader accepts;
- `database_runtime_compatibility` says whether a named retained runtime may
  read or read/write a database after the candidate migration;
- `bridge_contract` constrains the control-bridge API used by the control plane;
- `schema_epoch` provides a monotonic migration lineage check.

Publish the manifest as an OCI artifact addressed by digest, with a Cosign
signature and in-toto/SLSA provenance binding the source commit, builder, image
digest and manifest digest. Retain an SPDX or CycloneDX SBOM. The trusted root,
public-key identity, validity period and revocation status are distributed
through the infrastructure release contract. Production accepts verified
signatures and provenance, not an unsigned digest-only manifest.

### B2. Add release state to the control database

Add migrations for these logical records:

```text
application_releases
  id, source_commit, odoo_version, image_digest, manifest_digest,
  addon_versions, compatibility, change_class, published_at, status

tenant_release_adoptions
  workshop_id, database_id, release_id, source_release_id,
  registry_version, state, operation_id, backup_recovery_id,
  source_schema_epoch, target_schema_epoch, started_at, verified_at,
  activated_at, superseded_at, failure_class, evidence

runtime_release_slots
  runtime_key, slot, release_id, state, image_digest, started_at, verified_at
```

Application release states:

```text
candidate -> preflighting -> canary -> prepared -> active -> retained
                  |           |          |
                  +-----------+----------+-> failed
```

Tenant adoption states:

```text
pending -> isolating -> backing_up -> upgrading -> verifying -> prepared
              |             |           |            |
              +-------------+-----------+------------+-> failed
prepared -> active -> superseded
failed   -> restoring -> rolled_back
prepared -> restoring -> rolled_back
```

Only the listed transitions are legal. A transition function performs
compare-and-set validation and records its audit event. A partial unique index
allows at most one unfinished adoption (`pending`, `isolating`, `backing_up`,
`upgrading`, `verifying`, `prepared`, `failed` or `restoring`) per tenant, and
another allows at most one `active` adoption per tenant. Runtime slots have
exactly one active slot per runtime key. Cancellation is allowed only before
`upgrading`; after external mutation, the operation must converge through
verification, forward repair or `rolled_back`. A new release supersedes rather
than overwrites adoption history.

### B3. Add a durable release operation

Add operation kind `odoo.release.adopt` and queue `release-adoption`. It should
have its own worker and database role.

The worker performs:

1. Validate manifest signature/digest and immutable image availability.
2. Compare the candidate with the currently active release.
3. Acquire a fleet release fence and inventory every non-deleted primary tenant
   database and its installed modules. The fence blocks new public route
   activation and captures a fleet generation; provisioning may continue only
   if the new tenant remains unrouted until it joins this adoption or the next
   active release.
4. Reject tenants whose current release is outside the candidate compatibility
   range.
5. Select the canary and acquire a database advisory lock that is shared with
   restore, deletion and module-activation operations.
6. Put the canary into a visible maintenance state, remove its route, drain
   active HTTP/long-poll connections, stop tenant cron/background work and
   prove that the old runtime can no longer open that database.
7. Create and verify a tenant-specific recovery point after isolation. Record
   its immutable manifest and retention deadline before schema mutation.
8. Start a one-shot upgrade job from the candidate image. The old shared
   runtime may continue serving other tenants but has no route or background
   access to the isolated database.
9. Upgrade the full installed MakersBrain module set in dependency order. Do
   not upgrade only the module that changed; cross-module ownership migrations
   must run.
10. Verify registry loading, installed versions, migration ledger, required
   columns, critical external IDs and tenant health.
11. Leave the tenant unrouted in `prepared`. If any tenant fails, pause new
    upgrades. A class B tenant may return to the retained runtime only after its
    declared read/write compatibility is reverified. A class C tenant remains
    in maintenance until explicitly authorized forward repair succeeds or its
    recovery point is restored. Aborting the fleet restores every incompatible
    prepared tenant before any old-runtime route or cron is re-enabled.
12. Repeat isolation, per-tenant recovery and upgrade for the remaining tenants
    with bounded concurrency. Never interpret “repeat” as reusing the canary
    recovery point.
13. Start the inactive blue/green shared-runtime slot with the candidate digest.
    The first release uses two simultaneously addressable process slots, not an
    in-place container replacement.
14. Smoke-test the inactive slot against every prepared tenant using an internal
    route that is unavailable to public clients.
15. Persist an immutable fleet-activation intent containing the exact prepared
    tenant set, runtime slot, image digest and gateway configuration digest.
16. Ask the driver to atomically switch the gateway configuration with a stable
    action ID. On timeout or an unknown result, observe the active configuration
    before retrying. After the observed digest matches, mark the corresponding
    adoptions active, re-enable tenant cron/background work, remove maintenance
    state and perform exact-host read/write smoke tests. Reconciliation completes
    these records safely if the worker dies after the gateway switch.
17. Record activation evidence and retain the previous image, configuration and
    every recovery point for the declared rollback window.

No live tenant route points at candidate code before its database is compatible,
and no old runtime accesses a database while it is being upgraded. Fleet
preparation is therefore a controlled maintenance window for each tenant. If
the expected fleet size makes that window unacceptable, multiple runtime pools
become a separately approved design; the first implementation does not pretend
to provide zero-downtime class C migration.

### B4. Classify releases

Use three change classes:

| Class | Meaning | Rollback |
| --- | --- | --- |
| A | No database change | Switch runtime back to retained image. |
| B | Additive, retained runtime is declared read/write-compatible with the upgraded schema | Application rollback is allowed only when the candidate's directional compatibility entry names that exact retained release and verification succeeds. |
| C | Destructive or previous image incompatible | Forward repair or verified recovery restore; no automatic image-only rollback. |

The release pipeline must fail if a class or required directional compatibility
entry is missing. Class B compatibility is verified against both images during
preflight; class C automatically enters the recovery/forward-repair path and
never attempts image-only rollback.

### B5. Provide APIs and operator UI

Add operator routes:

```text
GET  /v1/platform/releases
GET  /v1/platform/releases/{id}
POST /v1/platform/releases/{id}/preflight
POST /v1/platform/releases/{id}/adopt
POST /v1/platform/releases/{id}/retry-failed-tenants
GET  /v1/platform/releases/{id}/tenants
```

All mutations require idempotency, an ETag for mutable release state, operator
authority and a typed confirmation for fleet activation.

The UI shows:

- source and image digests;
- addon-version changes;
- compatibility class;
- canary status;
- per-tenant progress and safe error;
- backup evidence;
- active and retained runtime slots.

### B6. Reconcile module versions continuously

Tenant reconciliation should compare:

- desired application release;
- runtime image digest;
- database-installed addon versions;
- enabled product capabilities;
- required bridge contract version.

Drift becomes a visible incident. Reconciliation must not start a schema
upgrade implicitly; it may enqueue a separately authorized adoption operation.

### Tests

- Upgrade versioned golden database and filestore fixtures for every declared
  `upgradeable_from` release. Each fixture is tied to a retained manifest and
  immutable image digest, never an arbitrary Git commit.
- Prove cross-module XML-ID handover migrations run.
- Kill the release worker after each phase and replay.
- Fail one tenant and prove the shared runtime is not swapped.
- Prove an identical adoption request replays to one operation.
- Prove a reused idempotency key with another release is rejected.
- Prove class B rollback only when the candidate manifest explicitly declares
  the retained runtime read/write-compatible with its upgraded schema and the
  two-image verification passes.
- Prove class C cannot perform image-only rollback.
- Prove the retained image and every tenant-specific recovery point remain
  available for the declared rollback window.
- Prove the old runtime, cron and long-poll workers cannot access a tenant from
  `isolating` until fleet activation or recovery completes.
- Prove release, restore, deletion and module activation cannot run concurrently
  for the same tenant.
- Provision a tenant during fleet preparation and prove it cannot become
  publicly routable on an incompatible release or escape the fleet snapshot.

### Acceptance

- A release can be adopted without shell access or manual SQL.
- Every tenant records the exact Odoo image digest and addon-version map.
- A failed tenant remains safely unrouted or is restored before the old runtime
  serves it; unaffected tenants continue on the old runtime.
- Every upgraded tenant has its own verified, retained recovery point and no
  request or background job crosses its isolation window.
- The operator can explain why any tenant is on its current release.

## 7. Workstream C — least-privilege runtime identities

### C1. Create PostgreSQL roles per process

Create non-owner login roles such as:

```text
control_api
control_membership_worker
control_provisioning_worker
control_invoice_worker
control_inventory_worker
control_email_worker
control_reconciliation_worker
control_lifecycle_worker
control_release_worker
control_backup_scheduler
control_driver_ledger
```

Keep migrations under a separate schema-owner role that is unavailable to
runtime containers.

Grant privileges through group roles and views/functions where direct table
access would be too broad. Revoke `CREATE` on shared schemas and all default
public privileges.

Infrastructure bootstrap, not an application migration, creates login roles,
generates their credentials and injects one distinct database URL per process.
Migrations create non-login group roles, object grants, security-definer
functions where justified and `ALTER DEFAULT PRIVILEGES` for future objects.
The schema owner owns all control objects; login roles own none and receive no
`SUPERUSER`, `CREATEDB`, `CREATEROLE`, `REPLICATION` or `BYPASSRLS` attribute.
Every security-definer function has a fixed safe `search_path`, explicit input
validation, a non-login owner and `EXECUTE` revoked from `PUBLIC`.

Document credential issuance, the security-approved maximum lifetime,
compromise-triggered emergency revocation and zero-downtime pool rollover. Use
short-lived/dynamic credentials where the production secret manager supports
them. Rotation first adds a new credential, drains the old connection pool,
verifies the new identity and then revokes the old one. Neither generated
credentials nor password hashes enter Git, migration SQL, Compose output, logs
or OpenTofu plan fixtures.

### C2. Enforce a secret matrix

| Process | Allowed secrets |
| --- | --- |
| API | API DB role, OIDC verification config, internal service-verification key references |
| Membership | membership DB role, Rauthy user-management key, tenant Odoo/Paperless refs |
| Provisioning | provisioning DB role, deployment-driver token |
| Invoice | invoice DB role, extraction broker token, tenant Odoo/Paperless refs |
| Inventory | inventory DB role, extraction broker token, tenant Odoo ref |
| Email | outbox DB role, mail-provider token, invitation signing capability |
| Reconciliation | reconciliation DB role, read/reconcile tenant refs |
| Lifecycle | lifecycle DB role, lifecycle driver token |
| Release | release DB role, release driver token, image/manifest verification keys |
| Backup scheduler | recovery scheduling DB role only; no restore key |

Split the Compose anchors accordingly. No generic worker anchor may carry all
provider credentials.

### C3. Restrict tenant secret resolution

Replace a mount of the entire tenant-secret tree with one of:

- a secret-resolver sidecar/API enforcing queue and workshop scope; or
- per-worker mounts containing only the required secret classes.

The preferred production shape is an authenticated resolver backed by
Infisical references. The file resolver remains acceptable for local Docker if
it enforces path type, workshop ID and caller role.

### C4. Remove the unserved identity queue

Remove `identity-operations` from the worker allowlist, status UI and release
contract. Keep current Rauthy membership work inside
`membership-provisioning`. Reintroducing a global identity/session queue
requires a real command, dedicated handler, database role, Rauthy credential,
contract entry and end-to-end test in the same change.

### C5. Keep Docker socket use development-only

The production driver must not mount the Docker daemon socket. Implement the
same authenticated driver contract through the planned Podman/systemd service.
Document the local Docker driver as a privileged development component and
isolate it from public networks.

### Tests

- Each process starts successfully with only its documented secrets.
- Removing one required grant fails the owning queue and no other queue.
- Email worker cannot read tenant integration secrets.
- Invoice worker cannot call tenant deletion or backup actions.
- Reconciliation worker cannot read restore credentials.
- Runtime roles cannot update/delete audit rows.
- Runtime roles cannot create schema objects.

### Acceptance

- Compromise of one worker does not grant every provider and lifecycle
  capability.
- The release contract and actual container environments match exactly.

## 8. Workstream D — secure invitations and command admission

### D1. Replace persisted plaintext invitation tokens

Use a versioned compact JWS capability following RFC 7515, RFC 8037 and the JWT
best-current practices in RFC 8725, signed by the email worker with Ed25519
(`alg=EdDSA`). The API receives only the public verification key. The payload
contains no email, name or workshop display value:

```text
protected = { alg: "EdDSA", typ: "mb-invitation+jwt", kid: key_id }
claims = {
  iss: "makersbrain-control", aud: "makersbrain-invitation",
  jti: invitation_id, gen: token_generation,
  iat: issued_at, nbf: issued_at, exp: expires_at
}
token = JWSCompact(protected, claims, ed25519_private_key)
```

Database fields:

```text
invitations.token_generation integer not null default 1
invitations.expires_at
invitations.accepted_at
invitations.revoked_at
```

The outbox stores `invitation_id`, `token_generation`, `issued_at`, `expires_at`,
`signing_key_id`, locale and template data. These fields are not capabilities.
The email worker signs exactly that immutable event, first verifying that the
invitation is neither revoked nor accepted and that the event generation still
matches the invitation. A delayed or superseded event is marked obsolete and
cannot mint the current generation. Resending atomically increments the
generation and inserts the new outbox event, immediately invalidating every
earlier link.

The email link is `/invitations/accept#token=<compact-jws>`. URL fragments are
not sent in HTTP requests. The browser immediately removes the fragment with
`history.replaceState`, retains the token only in memory and sends it in a POST
body over TLS; validation is also POST and never embeds a token in a path,
query, telemetry field or error. Responses use `Cache-Control: no-store` and
`Referrer-Policy: no-referrer`; proxy and application access logs redact the
invitation route and request bodies. The frontend must not load third-party
resources on this page.

Acceptance validates an allowlisted algorithm and media type, known non-revoked
`kid`, canonical claims, issuer, audience, clock bounds, generation, invitation
state and verified normalized email using constant-time signature verification.
Key rotation publishes overlapping public keys, signs only with the current
private key and retains old verification keys until all corresponding tokens
expire. Private signing material exists only in the email worker. HMAC is not
used because it would let a compromised public API mint capabilities.

### D2. Centralize command admission

Create one abstraction for mutating endpoints:

```text
admit_command(actor, scope, command_kind, idempotency_key,
              request_digest, expected_version)
```

It must:

- validate a bounded idempotency key;
- canonicalize and hash the semantic request;
- lock or create a command record;
- persist the original HTTP status and immutable response representation or
  result reference, and return that stored result for an identical replay;
- reject key reuse with another request digest;
- enforce `If-Match` where the target is versioned;
- create the audit event and durable operation in the same transaction.

Back it with a `commands` table keyed by `(actor_id, scope, command_kind,
idempotency_key)` and containing request digest, expected version, state,
operation ID, response status, response body/result reference and timestamps.
The digest covers the normalized actor, scope, command kind, target identifier,
semantic body and concurrency precondition using RFC 8785 JSON canonicalization
where JSON is involved. Secrets and raw invitation capabilities are never part
of a persisted digest input record.

Prefer an immutable result reference over copying a response containing
personal data. An inline response is permitted only when the data inventory
classifies its fields and the command retention policy is no longer than the
source resource's policy.

Admission order is fixed: authenticate and authorize; locate or create the
command; return a stored completed result for an identical replay; reject a
digest mismatch; then enforce the expected version for a new command. This
allows a successful replay after the resource has advanced without weakening
optimistic concurrency for new commands. In-progress identical replays return
the same operation or `202`, never start another mutation.

Database-only synchronous commands may complete without a queue operation, but
still persist their command result and audit event atomically. External or
long-running mutations must create a durable operation in the same transaction.

Use it for every public mutation, including workshop creation and lifecycle,
invitation create/resend/revoke/accept, member updates, ownership transfer,
capability activation/restriction, recovery and release adoption. Document any
internal mutation exemption with an equivalent replay/concurrency mechanism.

### D3. Add proper ETags

Return strong ETags with RFC 9110 `If-Match` semantics, derived from stable
resource versions. Do not use weak validators for mutation preconditions:

```text
ETag: "workshop-<uuid>-v<version>"
```

Require `If-Match` for:

- workshop settings/status changes;
- member role changes and removal;
- ownership transfers;
- capability state changes;
- release activation and retry policy changes.

Return `428 Precondition Required` when absent and `412 Precondition Failed`
when stale.

### D4. Enforce append-only audit at the database boundary

The audit writer role receives `INSERT` and `SELECT`, never `UPDATE` or
`DELETE`. Add a trigger that rejects mutation by runtime roles. Database-owner
maintenance remains a separately audited operational capability.

Include request digest, result class and release identity in relevant audit
details, never secret or document payloads. Audit rows use the random
`audit_subject_id` described by the privacy workstream rather than email, OIDC
subject or another externally meaningful identifier.

### Tests

- Database rows contain no invitation plaintext or complete acceptance URL.
- A resend invalidates the previous token immediately.
- An identical command returns the stored original status/result and operation
  reference even if the resource version has since advanced.
- The same key with another payload returns conflict.
- Two concurrent updates with one ETag allow exactly one winner.
- Runtime roles cannot alter audit history.

## 9. Workstream E — one configuration and runtime contract

### E1. Define a typed configuration specification

Create a source file describing each setting:

```text
name
owner process
required/optional condition
secret/non-secret
development default policy
validation rule
release-contract description
```

Generate or validate:

- `deploy/.env.example`;
- `bootstrap-local-env.sh` output;
- Compose environment blocks;
- `release-contract.json.required_environment`;
- Rust startup configuration tests;
- operator documentation.

### E2. Fix extraction-broker token provisioning first

Add `DOCUMENT_EXTRACTION_TOKEN` to the example and bootstrap generator. Reject
an empty `BROKER_TOKEN` or `CONTROL_EXTRACTION_BROKER_TOKEN` before Compose
starts dependent services.

### E3. Validate conditional groups atomically

Examples:

- an enabled Azure provider requires endpoint and key;
- a selected vision provider requires endpoint, key and model;
- portable backup requires the complete writer/reader/encryption set;
- a public tunnel requires a token file and allowed development domain;
- production forbids fixture mail and self-signup.

### E4. Add contract-drift CI

CI fails when:

- Compose references an undocumented variable;
- a required contract variable is absent from the owning process;
- a secret is placed in the wrong process;
- a queue is declared but has no process/handler;
- an image lacks its declared health endpoint;
- a mutable image tag is used in a non-development release manifest.

## 10. Workstream F — capability registry and entitlement policy

### F1. Present capabilities, not module names

Initial registry entries covered by this improvement programme:

| Capability | Internal realization | Dependencies |
| --- | --- | --- |
| Ceramics production | `mb_ceramics_workflow`, compliance/base dependencies | none |
| Kilns and firings | `mb_ceramics_firing` | Ceramics production or explicit ceramics base policy |
| Connected kiln | `mb_kiln_bridge` | Kilns and firings |
| Labels and POS QR | `mb_label`, `mb_label_pos` | POS availability |
| Depot sales | `mb_depot` | commercial base |
| SumUp payments | SumUp addon set | relevant sales/POS capability |
| Product capture | `mb_inventory_capture` | none |
| Documents | Paperless service | none |
| Invoice capture | `mb_invoice_capture` | Documents |
| Azure invoice extraction | extraction-broker provider | Invoice capture |
| Inventory AI fallback | extraction-broker provider | Product capture |

The active tenant must gain an explicit supported path to
`mb_ceramics_workflow`; shipping it in the image but omitting it from the
registry is not a complete deployment path.

Existing catalogue-sync and scraper capabilities remain unchanged and outside
this workstream.

### F2. Separate desired, installing and applied states

Use states:

```text
available -> requested -> installing -> enabled
                             \-> failed
enabled -> restricted
```

`restricted` disables new use through entitlement/policy but retains records.
Do not uninstall an Odoo module automatically. Each registry entry declares an
enforcement adapter: Odoo security group/configuration gate, control-plane API
gate, external-service credential suspension, or a documented combination.
Moving to `restricted` must successfully apply and verify that adapter; changing
only the control-database state is not sufficient. Historical records remain
readable where the product and legal policy require it.

### F3. Enforce entitlement before activation

Activation must check:

- plan permits capability;
- entitlement is active and unexpired;
- dependencies are applied, not merely requested;
- the active application release contains the required implementation;
- the tenant database is at a compatible release.

Record entitlement version on the activation operation so later retries cannot
silently use a changed commercial decision.

### F4. Version the capability registry

Move the registry to a versioned data structure shared by the release
manifest, API and worker. Database checks must not require a migration for every
new capability key; use registry tables keyed by `(registry_version,
capability_key)` and seeded by the application release rather than an
ever-growing SQL `CHECK` list. Tenant desired/applied state and activation
operations pin the registry version, application release, entitlement version
and resolved implementation set so retries and audit history never reinterpret
an old decision using a newer registry.

## 11. Workstream G — modularize the Rust implementation

Keep one crate initially and split by responsibility:

```text
src/api/
  mod.rs
  platform.rs
  workshops.rs
  memberships.rs
  capabilities.rs
  recovery.rs
  releases.rs
  internal.rs
  command_admission.rs

src/workers/
  mod.rs
  membership.rs
  provisioning.rs
  extraction.rs
  lifecycle.rs
  releases.rs
  email.rs

src/driver/
  mod.rs
  contract.rs
  ledger.rs
  docker_client.rs
  postgres.rs
  odoo.rs
  paperless.rs
  redis.rs
  rauthy.rs
  gateway.rs
  recovery.rs

src/contracts/
  api.rs
  deployment.rs
  release.rs
  extraction.rs
```

### G1. Refactor by behavior-preserving slices

For each extraction:

1. Add characterization tests around existing behavior.
2. Move types and functions without changing public behavior.
3. Make dependencies explicit through small context structs/traits.
4. Run format, clippy, unit and PostgreSQL integration tests.
5. Commit a focused refactor before changing behavior.

Do not combine the whole split with release-management features in one commit.

### G2. Restrict dependency direction

```text
transport -> application -> domain
application -> ports <- integrations
persistence implements application repositories
```

Domain types must not depend on Axum, SQLx, Docker JSON or provider response
types. Provider normalization happens in adapters.

### G3. Extract crates only when justified

Possible later crates:

- `control-contract` when another repository consumes generated Rust types;
- `deployment-driver-contract` when Podman and Docker implementations are built
  independently;
- `extraction-contract` when broker and worker release independently.

File size alone is not sufficient reason for independently versioned crates.

## 12. Workstream H — typed API and generated clients

### H1. Replace the hand-written OpenAPI path list

Define typed request, response and error schemas next to handlers and generate
OpenAPI 3.1 from those definitions. Include:

- path/query/header parameters;
- request bodies;
- response schemas for every status;
- `Idempotency-Key`, `If-Match` and `ETag` semantics;
- public versus operator versus internal security schemes;
- operation IDs and deprecation metadata.

Internal routes belong in a separate internal contract or are explicitly
tagged and excluded from the public browser client.

### H2. Generate the frontend client

Generate TypeScript types and a small fetch client during the build. Handwritten
UI view models may wrap generated contracts, but must not duplicate wire types.

### H3. Add compatibility checking

CI compares the public OpenAPI document with the previous released contract and
rejects unclassified breaking changes. A deliberate break requires a new API
version or an explicit compatibility decision.

### Acceptance

- Every router operation exists in OpenAPI automatically.
- Every public schema used by the web app is generated.
- Removing or changing a response field fails compatibility CI.

## 13. Workstream I — remove network waits from database transactions

The synchronous product lookup currently holds a PostgreSQL transaction and
transaction advisory lock while calling the extraction broker.

### I1. Introduce a cache-fill lease

Add a bounded lease record:

```text
product_lookup_fills
  provider, schema_version, gtin14, state, leased_by,
  lease_expires_at, last_error, updated_at
```

Flow:

1. Read positive/negative cache without a transaction.
2. Atomically acquire or observe a short fill lease.
3. Commit.
4. The lease owner calls the broker outside a database transaction.
5. Store the normalized result and release the lease in a short transaction.
6. Concurrent callers either receive a bounded `202/retry_after`, wait briefly
   outside PostgreSQL, or use a recently stale safe cache result.

For the best UX, keep a bounded synchronous fast path but never hold a database
transaction across the network request.

### I2. Define provider ownership

The extraction broker owns external product-lookup credentials, throttling and
provider failover. The control API owns tenant admission, cache identity and
safe normalized responses. Changes to the sibling catalogue scraper or its
proxy behavior are explicitly outside this plan.

## 14. Workstream J — observability and operator experience

### J1. Add durable worker heartbeats

Record:

```text
worker_id, queue, release_id, started_at, last_heartbeat_at,
active_operation_id, shutdown_at
```

Alert when a required queue has no fresh worker.

### J2. Export metrics

Minimum metrics:

- HTTP latency/error rate by route class;
- queue depth and oldest due age;
- lease renew failures and abandoned leases;
- operation attempts, dead letters and unknown outcomes;
- membership/service drift age;
- release adoption status and tenant lag;
- extraction requests, provider latency, throttling and plan usage;
- backup age, verification failures and rehearsal age;
- Paperless/Odoo/Rauthy integration latency and availability.

Use OpenTelemetry-compatible traces and Prometheus-compatible metrics. Keep
document content, emails, tokens and provider payloads out of labels and spans.

### J3. Improve operator views

Add:

- stale-worker and queue-health panel;
- release fleet matrix;
- tenant release/drift history;
- recovery freshness and rehearsal status;
- credential-rotation due dates without secret values;
- safe retry and reconciliation actions;
- links from a failed operation to the relevant release, tenant and recovery
  evidence.

### J4. Separate platform authority from email configuration

Use a stable platform-role record bound to the internal user/identity. Keep
`CONTROL_OPERATOR_EMAILS` only as a bootstrap mechanism. Production platform
actions use a separately deployed operator client and OIDC audience, sharing a
source package with the artisan frontend but not its client registration or
session. Require step-up authentication for deletion, restore and fleet release
activation.

## 15. Workstream K — verification strategy

### K1. Unit and contract tests

- domain role/permission matrix;
- release compatibility decisions;
- capability dependency graph;
- invitation signing and generation invalidation;
- idempotency digest behavior;
- provider normalization and redaction;
- release and deployment manifest parsing.

### K2. PostgreSQL integration tests

- last-owner protection;
- command replay and payload mismatch;
- ETag compare-and-set behavior;
- operation leasing and heartbeat expiry;
- audit immutability by runtime roles;
- per-role privilege matrix;
- release/adoption uniqueness and state transitions;
- recovery/adoption serialization;
- cache-fill lease recovery.

### K3. Full topology tests

Provision two workshops and prove:

- exact-host routing cannot select the other database;
- a forged database-filter header is overwritten;
- each Rauthy subject enters only its authorized Odoo/Paperless tenant;
- one Paperless Redis identity cannot access another prefix;
- tenant secrets cannot be resolved by the wrong worker role;
- backup, restore and release operations on one tenant do not interrupt the
  other tenant;
- module activation cannot exceed entitlement.

### K4. Failure injection

Terminate the worker or driver after each provisioning, release and restore
phase. Exercise:

- Rauthy unavailable;
- Odoo registry/migration failure;
- Paperless unavailable;
- extraction throttling and timeout;
- Docker/Podman driver unknown outcome;
- backup upload interruption;
- corrupt or wrong-key recovery input;
- route reload failure;
- database connection exhaustion.

Every scenario must converge safely or leave a visible, non-routable maintenance
state with an operator action.

### K5. Security and secret-leak tests

Scan:

- control database JSON/text columns;
- application and proxy logs;
- OpenAPI responses;
- operation checkpoints;
- backup manifests;
- image history and Compose config;
- OpenTofu state fixtures.

Seed recognizable canary secrets and fail if any appear outside their approved
secret store/process.

## 16. Workstream L — GDPR and privacy engineering

This workstream implements GDPR Articles 5, 12–23, 25, 30, 32–35 and 44 where
they apply. It is engineering evidence, not a substitute for the controller's
legal assessment. The controller, processors, lawful bases, retention periods
and international-transfer mechanisms must be approved by the accountable
organization and recorded before production processing.

### L1. Maintain a machine-readable personal-data inventory

For every field, event, log and backup containing personal data, record:

```text
data category and exact fields
purpose and lawful basis
controller/processor role and subprocessors
data subjects and source
owning service and storage locations
authorized roles and recipients
retention trigger and deletion/anonymization action
international transfer location and safeguard
data-subject request lookup key
```

At minimum inventory user email, identity issuer/subject, membership and role
history, invitation recipient/delivery metadata, audit actor references,
operator actions, support evidence and IP/user-agent data if any layer retains
them. CI fails when a schema, API, event or telemetry field marked as personal
data is absent from the inventory.

### L2. Minimize and pseudonymize by default

- Use internal UUIDs in operations, audit, metrics and traces; resolve names or
  email only in an authorized UI view when needed.
- Do not copy identity tokens, email addresses, document contents, free-form
  provider payloads, IP addresses or user agents into operation payloads,
  checkpoints, metric labels or trace attributes.
- Normalize email only for identity matching; do not use its hash as an
  allegedly anonymous identifier because the input space is guessable.
- Disable third-party analytics, advertising cookies and session replay in the
  artisan and operator applications unless a separately approved consent design
  is introduced. Essential authentication cookies are `Secure`, `HttpOnly`
  where browser access is unnecessary and `SameSite=Lax` or stricter.
- Encrypt personal data in transit and encrypted storage/backup at rest. Keep
  encryption and signing keys in the approved secret manager with rotation,
  revocation and access evidence.

### L3. Implement retention and erasure as durable operations

Create a versioned retention policy and scheduled jobs with dry-run evidence.
Do not invent legal retention periods in code: each period has a named business
owner, legal rationale, start event and approved duration. Expired invitations,
outbox delivery metadata, authentication/security logs, operation details,
support exports and recovery artifacts are deleted or irreversibly anonymized
according to that policy.

Erasure never rewrites append-only security evidence. Audit events that may need
retention use a random audit-subject identifier whose separately protected
identity mapping has its own lawful basis and retention. Erasure deletes or
crypto-shreds that mapping when no retention basis remains, leaving minimum
unlinkable event facts without updating the audit row. Database backups remain
immutable for their short approved retention period, are excluded from normal
restoration except for disaster recovery, and reapply outstanding erasure
tombstones immediately after restore.

Backups receive at least the security level of production data. Production uses
the 3-2-1 pattern with an encrypted, geographically separate and offline or
logically isolated copy, plus scheduled integrity and restoration tests. Access
to backup content is separately authorized and audited.

### L4. Support data-subject requests

Add authenticated, audited workflows for access, rectification, erasure,
restriction, portability and objection. A request records identity verification,
scope, applicable decision/exemption, due date, approver, exports and completion
evidence without copying the supplied identity documents into the control
database. Exports are encrypted, time-limited, single-use and cover every
inventory location using a stable subject lookup map.

Completion fans out to every applicable processor/subprocessor and records its
acknowledgement. Restriction applies an enforceable processing hold rather than
only a UI label; only storage and specifically approved exceptional processing
remain possible while the restriction is active.

Requests involving workshop business records are routed to the controller and
cannot be fulfilled by deleting accounting or compliance records blindly.
Operator UI tracks the normal one-month response deadline, records any lawful
extension and notification to the subject, and escalates before expiry without
exposing the request to unrelated workshop operators.

### L5. Record processing, processors and transfers

Maintain versioned records of processing activities, processor/subprocessor
contracts, hosting regions and transfer safeguards. Provider enablement is
blocked when required processor terms, regional configuration or transfer
assessment are absent. Production configuration records only references and
approval versions, not contract documents or personal data.

The deployment preference is a Paris-region service, with Azure West Europe as
the EEA fallback. Personal data must remain in the EEA by default. A move to a
non-EEA region or a provider involving a non-EEA transfer requires a separately
approved transfer assessment and safeguard before enablement.

### L6. Privacy and security incident readiness

Create a breach workflow that records discovery and controller-awareness time,
affected data categories, subjects/tenants, containment, risk assessment,
controller/DPO decision and notification evidence. It must surface the GDPR
72-hour supervisory-authority deadline from awareness where notification is
required, without assuming every incident is notifiable. Preserve evidence
under a documented legal hold that is scoped, approved, time-bounded and
released explicitly.

Complete and record the formal DPIA threshold assessment before production. The
project adopts a DPIA as an internal production gate even if the assessment
concludes that Article 35 does not make it legally mandatory, because the system
combines tenant isolation, identity, accounting/document integrations and
automated extraction. Reassess it for new providers, new categories of personal
data, material profiling/automation or international-transfer changes.

### L7. Normative privacy references

Implementation and review use the authoritative text and regulator guidance:

- [GDPR Chapter III — data-subject rights](https://www.cnil.fr/fr/reglement-europeen-protection-donnees/chapitre3);
- [GDPR Chapter IV — controller, processor, security and breach duties](https://www.cnil.fr/fr/reglement-europeen-protection-donnees/chapitre4);
- [EDPB Guidelines 4/2019 on data protection by design and by default](https://www.edpb.europa.eu/documents/guideline/guidelines-42019-on-article-25-data-protection-by-design-and-by-default_en);
- [CNIL guidance for implementing data-subject rights](https://www.cnil.fr/fr/preparer-lexercice-des-droits-des-personnes);
- [CNIL backup security guidance](https://www.cnil.fr/fr/securite-sauvegarder);
- [CNIL DPIA threshold and method guidance](https://www.cnil.fr/fr/ce-quil-faut-savoir-sur-lanalyse-dimpact-relative-la-protection-des-donnees-aipd).

### L8. Tests and acceptance

- Seed personal-data canaries and prove they never enter disallowed logs,
  metrics, traces, operation payloads, checkpoints, images or infrastructure
  state.
- Execute access, rectification, restriction, portability and erasure against a
  two-tenant fixture; prove tenant and operator authorization boundaries.
- Restore a backup containing an erased subject and prove the erasure tombstone
  is reapplied before the tenant becomes routable.
- Prove expired data is removed according to the versioned policy and that a
  legal hold affects only its explicit scope.
- Retain a reviewed data inventory, processing record, DPIA, subprocessor list,
  transfer assessment, retention report and incident rehearsal as release
  evidence.

## 17. Delivery sequence

### Phase 0 — document and characterize

1. Create the current-state architecture document.
2. Add characterization tests for API, worker and driver behavior.
3. Define the configuration specification and release-manifest schema.
4. Correct the extraction-token bootstrap drift.
5. Create the personal-data inventory and record the controller-approved
   lawful bases, processors, transfer safeguards and retention-policy owners.

Gate: a clean checkout produces a complete validated local configuration, and
the documented process/queue list matches the executable topology. No
production-like personal data is admitted until its inventory and purpose are
approved.

### Phase 1 — command and secret safety

1. Implement Ed25519-signed, fragment-delivered invitation capabilities with
   generation-pinned outbox events and signing-key rotation.
2. Centralize command admission, canonical request digests and stored replay
   responses.
3. Add ETags and compare-and-set updates.
4. Enforce append-only audit privileges.
5. Bootstrap distinct database logins and split worker secret environments.
6. Enable privacy-safe telemetry defaults and retention jobs.

Gate: secret canaries and role-matrix tests pass; every public mutation has
replay and stale-write tests.

### Phase 2 — Odoo release adoption

1. Add release/adoption schema.
2. Publish immutable Odoo release manifests.
3. Implement tenant isolation, per-tenant recovery and one-shot upgrade jobs.
4. Add canary, fleet preparation, blue/green runtime slot switch and
   verification.
5. Add release APIs and operator UI.

Gate: every declared retained-release fixture upgrades for two isolated tenants;
a forced tenant failure prevents runtime activation, and no old-runtime request
or background job reaches an isolated database.

### Phase 3 — product capability correction

1. Version the capability registry.
2. Add Ceramics production and `mb_ceramics_workflow`.
3. Correct dependency edges such as Connected kiln -> Kilns and firings.
4. Enforce entitlement and release availability.
5. Add restricted state without automated uninstall.

Gate: an owner can enable a permitted capability through the UI and the exact
Odoo release/module evidence becomes visible.

### Phase 4 — modularization and typed contracts

1. Split API, workers and driver through behavior-preserving commits.
2. Generate OpenAPI from typed handlers.
3. Generate the frontend client.
4. Add compatibility checks.
5. Move product lookup off network-held database transactions.

Gate: no route or behavior is lost, public contract compatibility passes, and
the synchronous lookup path holds no transaction during provider I/O.

### Phase 5 — operations and production rehearsal

1. Add heartbeats, metrics, tracing and alert rules.
2. Add platform roles and step-up operator actions.
3. Deploy through staging infrastructure identities and Podman driver.
4. Run full isolation, failure and recovery tests.
5. Rehearse class A/B rollback and class C recovery.
6. Exercise data-subject requests, retention, backup erasure replay and breach
   response; retain the reviewed DPIA and processing records.

Gate: retained evidence satisfies every acceptance criterion below.

## 18. File-level implementation map

Expected areas of change:

```text
CONTROL-PLANE-DESIGN.md                  historical redirect after migration
CONTROL-PLANE-ARCHITECTURE.md            new current-state document
CONTROL-PLANE-ROADMAP.md                 new remaining-work roadmap
control-plane/src/api.rs                 split into api/*
control-plane/src/worker.rs              split into workers/*
control-plane/src/docker_driver.rs       split into driver/*
control-plane/src/modules.rs             versioned capability registry
control-plane/src/openapi.rs             replaced by generated typed contract
control-plane/src/persistence.rs         repositories, command admission, roles
control-plane/src/config.rs              typed configuration specification consumer
control-plane/migrations/                roles, releases, capabilities, leases
control-plane/deploy/compose.yml          per-process environments and roles
control-plane/deploy/.env.example         generated/validated configuration
control-plane/deploy/bootstrap-local-env.sh
control-plane/deploy/release-contract.json
control-plane/privacy/data-inventory.yaml     field-level processing inventory
control-plane/privacy/retention-policy.yaml   approved triggers and actions
control-plane/privacy/processors.yaml         regions, processors and safeguards
control-plane/privacy/dpia.md                 reviewed risk and mitigations
control-plane/web/src/lib/                generated API client and release views
control-plane/web/src/routes/platform/    releases, workers, recovery evidence
addons/mb_control_bridge/                 release/module evidence endpoints
makersbrain-infra                         Podman driver, identities, metrics, release adoption
```

Every schema change requires a forward migration and PostgreSQL integration
test. Every release-contract change requires Compose validation and an
infrastructure consumer test.

## 19. Final acceptance criteria

The improvement programme is complete when:

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

## 20. Explicit non-goals

Do not include these in the improvement programme without a new trigger:

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

## 21. Decisions required before gated production

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
