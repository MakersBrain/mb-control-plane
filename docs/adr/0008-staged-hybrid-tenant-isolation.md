# ADR 0008: Stage database tenant isolation behind explicit execution scopes

- Status: accepted
- Date: 2026-08-22
- Decision owners: control-plane maintainers

## Context

At the time of this decision, HTTP authorization and workshop predicates were
the control plane's tenant boundary. PostgreSQL granted separate runtime roles
by process, but those grants were table-level: a role that could read or update
a workshop-owned table could do so for every workshop row in that table. No
table in the `control` schema had row-level security enabled and no runtime path
set transaction-local database tenant context.

This is not only an API concern. The processes have materially different data
access patterns:

- `control_api` served workshop routes, fleet-wide platform routes, identity
  bootstrap, and internal machine routes through one connection pool;
- workers lease operations before a workshop is known and several recovery
  loops scan workshop-owned tables across the fleet;
- the backup scheduler intentionally discovers due work across workshops;
- the release worker and driver ledger coordinate fleet-wide release state;
- privacy work can span multiple workshops for one data subject or legal hold;
- the migration owner must see all rows and remains the table owner.

The runtime roles are `NOSUPERUSER`, `NOCREATEDB`, `NOCREATEROLE`,
`NOREPLICATION`, and `NOBYPASSRLS`. That makes forced RLS technically viable,
but a policy based only on `control.workshop_id` would currently either break
legitimate fleet work or need a permissive machine-role exception that adds no
tenant defense. The API's mixed tenant/platform pool presents the same problem.

The feasibility characterization in `tests/tenant_isolation.rs` executes as
each deployed runtime role with `SET LOCAL ROLE`. It creates two workshops, sets
a transaction-local workshop GUC, and directly attempts cross-workshop reads
and writes on the still-unprotected characterization tables. It also names the
partially protected catalog surface. The test is ignored because it requires a
disposable PostgreSQL 17 administrator endpoint and global role creation. It is
still characterization evidence, not the complete isolation acceptance matrix.

## Decision

Adopt a **staged hybrid** design:

1. Keep explicit workshop predicates and narrow, workshop-scoped persistence
   operations as the mandatory defense now. Child identifiers never replace
   the owning `WorkshopId`; reads and mutations constrain both.
2. Add forced RLS only after an executable has distinct database execution
   scopes. RLS starts with directly workshop-owned, high-impact tables rather
   than being enabled schema-wide.
3. Keep fleet coordination tables and genuinely cross-workshop workflows behind
   process-specific ACLs and bounded coordination operations. Do not give a
   tenant-scoped pool a policy escape based on a caller-set Boolean GUC.

This selects the hybrid option over RLS-only or persistence-only. Scoped
persistence can be applied without invalidating current worker behavior. Forced
RLS supplies a later database backstop for missed predicates, but only once the
connection and transaction semantics below are implemented and exercised.

## Required execution scopes

### Human tenant scope

Workshop HTTP operations will use a tenant-only pool whose login cannot assume
a platform or fleet role. Every database operation against an RLS-protected
table runs in an explicit transaction:

```sql
begin;
select set_config('control.workshop_id', '<validated workshop uuid>', true);
-- scoped statements
commit;
```

The third argument to `set_config` is always `true`. Session-level `SET`, pool
`after_connect` tenant state, and statements on a bare pooled connection are
forbidden. A policy obtains the context with a fail-closed helper: absent,
empty, or malformed context yields no tenant rows and rejects tenant inserts or
updates. The helper must not be `SECURITY DEFINER` and the tenant login must not
own protected tables or have `BYPASSRLS`.

The workshop UUID comes only from the already-authorized `WorkshopScope`. The
database context is defense in depth; it does not authenticate a principal or
replace permission and authority-epoch checks.

### Platform and internal-machine scope

Platform and internal routes use a separate pool and login with separately
reviewed table/function grants. They never turn a tenant policy into a platform
policy by setting `control.platform = true`. Cross-workshop mutations use
narrow application operations, and sensitive exceptions should become
parameterized functions with fixed `search_path` where ordinary grants cannot
express the boundary.

The original single `control_api` pool therefore had to be split before API RLS
was enabled. That split now exists: `control_tenant_api` is reachable only
through `TenantStore`/`WorkshopTransaction`, while platform discovery and
internal-machine operations retain `control_api`. Pool selection happens after
route authentication/authorization, not from untrusted path or body data.

### Worker tenant scope

Queue leasing and heartbeat operations remain fleet coordination. Once a lease
provides `operation.workshop_id`, tenant data access moves into an explicit
transaction with the same transaction-local context rule. A worker may process
a global operation only when its operation kind declares that scope.

Fleet recovery scans of tenant tables must first be replaced by one of:

- a durable operation/coordination-table scan that returns workshop identity;
- a role-specific, bounded claim function returning the claimed row and its
  workshop; or
- an explicitly documented fleet operation executed by a fleet-only role.

No worker receives an unrestricted RLS policy merely because it is a machine.
The backup scheduler, release worker, privacy worker, lifecycle worker,
reconciliation worker, and driver ledger need individual workflow review; they
must not be treated as interchangeable tenant workers.

### Migration scope

Only the one-shot migration login owns schema objects. Runtime logins remain
non-owners and `NOBYPASSRLS`. Protected tables use both `ENABLE ROW LEVEL
SECURITY` and `FORCE ROW LEVEL SECURITY`; catalog tests verify both flags,
policies, owners, and role attributes. Migration and rollback procedures run as
the migration owner, never through a runtime pool.

## Initial RLS candidates and exclusions

The first candidate set is the directly keyed, high-impact human-API surface:
`memberships`, `invitations`, `ownership_transfers`, `carrier_secrets`,
`webshop_domains`, `webshop_email_domains`, `workshop_modules`,
`service_instances`, `odoo_databases`, `workshop_recovery_points`,
`workshop_recovery_components`, and `workshop_recovery_rehearsals`.

The maintained staged-rollout inventory is
[`tenant-isolation-first-wave.json`](../tenant-isolation-first-wave.json). It
records each candidate's tenant key, application touch paths, triggers, foreign
keys, security-definer functions, current runtime grants, and next review. Its
`staged_policies_enforced` status records the candidates protected by forced
RLS. Every other table remains explicitly not ready;
inventory coverage is a prerequisite, not isolation evidence or authorization
to add another policy.

Implemented first policy slice (2026-08-22): the API has distinct platform and
tenant logins/pools, `WorkshopTransaction` installs only transaction-local
`control.workshop_id`, and direct first-wave workshop reads plus revalidated
workshop mutations use that scope. Ownership-transfer acceptance performs its
platform discovery first and then re-reads and locks the transfer through the
tenant transaction. Migration `0005_tenant_api_identity` adds the non-security-
definer fail-closed context helper and enables and forces RLS on
`ownership_transfers`, with distinct migration-owner, platform-discovery, and
tenant policies. This proves one staged candidate, not schema-wide tenant
isolation. The disposable-PostgreSQL CI test exercises this candidate through
the production `TenantStore`, same-connection reuse, missing and malformed
context, catalog flags, role non-membership, and direct cross-tenant CRUD
attempts.

Implemented recovery-component policy slice (2026-08-22): migration
`0016_recovery_component_tenant_rls` removes the unused platform-API table
grant and enables forced RLS on `workshop_recovery_components`. The only runtime
policies belong to the lifecycle-worker and driver-ledger identities; both
require the transaction-local workshop context and a matching parent recovery
point. Those workflows already receive only `TenantStore` after their fleet
admission step and keep database transactions outside provider and filesystem
effects. Direct production-role SQL tests cover same-workshop behavior,
cross-workshop reads and mutations, malformed or missing context, table ACLs,
policy metadata, and the real transaction capability. The recovery parent
remains unprotected until its scheduler, release, privacy, and API workflows
are split.

Implemented worker execution-scope slice (2026-08-22): leased rows are decoded
through a closed `OperationKind` mapping before dispatch. Thirteen kinds require
a non-nil workshop; release adoption, retention, and data-subject requests
require fleet scope. Unknown kinds, queue mismatches, nil workshops, and scope
nullness mismatches fail as contract drift before handlers and failure callbacks
run. The membership worker retains `Store` for fleet lease/heartbeat/completion
and gives `membership.reconcile` and `entitlement.apply` only a cloned,
transaction-only `TenantStore` capability. Its snapshot and result SQL runs in
short `WorkshopTransaction`s, never across outbound provider calls. A cloned
pool is intentional: the queue already has a distinct runtime login, and a
second connection pool with the same identity would add no database boundary.
The production-login PostgreSQL gate executes a real membership-worker lease,
scoped transaction, heartbeat, and completion. No new table is claimed as
RLS-protected by this slice.

Implemented resource-ownership slice (2026-08-22): email delivery receives only
the validated workshop plus `TenantStore`; it resolves and mutates outbox rows
through short workshop transactions before and after provider I/O. Migration
`0006_outbox_tenant_ownership` makes every outbox row directly workshop-owned,
binds invitation workshop and recipient to the authoritative invitation, closes
the allowed invitation/transactional metadata shapes, and adds a composite
tenant foreign key for branded-domain test mail. This is relational ownership,
not an RLS policy. Lifecycle execution now checks all payload database/recovery
relationships inside `WorkshopTransaction` before progress, mutation, or driver
I/O. Its post-provider and failure transitions retain workshop and operation
predicates, and erasure replay discovery joins the operation's source recovery
to workshop-owned tombstones.

Implemented lifecycle capability slice (2026-08-22): lifecycle payloads decode
once into a closed action enum. The handler and every production helper,
including terminal compensation, receive `TenantStore` or
`WorkshopTransaction` but never `Store`. Validation and all preparation changes
commit atomically before deployment-driver I/O; finalization and erasure replay
bookkeeping use fresh short transactions. Migration
`0007_lifecycle_resource_ownership` adds direct workshop keys to recovery
components and restore replays, composite ownership foreign keys across service,
database, recovery, deletion, rehearsal, replay, tombstone, and release-adoption
relationships, and corrects lifecycle-worker grants. It intentionally adds no
RLS policy: backup scheduler, fleet release, privacy, and driver-ledger paths
still require their own bounded execution designs. The queue's post-lease Rust
capability is tenant-only; the tables' full multi-role workflow matrix is not.

Implemented scheduler capability slice (2026-08-22): the backup scheduler
binary delegates to a feature-owned service with a private, bounded fleet
discovery capability and a transaction-only `TenantStore` for every mutation.
Migration `0008_scheduler_rehearsal_leases` adds durable attempt budgets,
expiring leases, fencing tokens, one-running-rehearsal-per-workshop enforcement,
retry indexes, and column-scoped scheduler updates. Driver HTTP never runs in a
database transaction, and rehearsal outcome plus audit event commit atomically.
This still does not authorize rehearsal RLS: production behavior and every
remaining API/driver path must pass the workflow matrix first.

Implemented rehearsal-policy slice (2026-08-24): migration
`0042_rehearsal_tenant_rls` enables and forces RLS on
`workshop_recovery_rehearsals` with command-specific policies. The platform API
retains fleet-wide read-only visibility for status and metrics, and the backup
scheduler retains read-only visibility for its bounded discovery queries. The
API's inherited mutation grants are removed. Scheduler inserts and updates are
visible only when their row and recovery parent match the fail-closed,
transaction-local workshop context already installed by `TenantStore`; no
runtime role receives a delete policy. Production-role tests prove fleet reads,
same-workshop writes, missing and malformed context, cross-workshop denial,
catalog flags, policy metadata, and the narrowed ACLs. This policy protects the
rehearsal ledger's runtime mutations; its recovery-point parent remains pending
until release and privacy access are split.

Implemented recovery-point ACL preparation (2026-08-24): migration
`0043_recovery_point_runtime_acl_pruning` removes the release worker's stale
direct SELECT/INSERT/UPDATE grant and the privacy worker's stale direct SELECT
grant on `workshop_recovery_points`. Neither worker contains direct SQL for the
table. Interrupted release review retains its fixed-search-path
`SECURITY DEFINER` capability, which performs the bounded recovery-evidence
read without restoring general table access. Production-role tests prove the
removed operations fail with PostgreSQL privilege errors. This is least-
privilege preparation, not RLS: platform fleet release preparation and status,
plus the driver ledger's bounded fleet release read, still need explicit policy
classification before the recovery parent can be protected.

Implemented platform recovery-point capability slice (2026-08-24): migration
`0044_platform_recovery_capabilities` separates the platform API's intentional
fleet status reads from its two recovery-point writes. Direct platform
INSERT/UPDATE/DELETE privileges are removed. Workshop deletion and fleet
release preparation instead call distinct, fixed-search-path `SECURITY DEFINER`
functions that validate the exact durable operation and derive ownership,
requester, component scope, label, format, and release provenance from trusted
ledger state. Both calls remain inside their original transactions, preserving
command, deletion, and fleet-adoption atomicity. Production-role tests verify
the narrowed ACL, capability metadata, PUBLIC denial, and direct mutation
failure. This did not yet enable recovery-point RLS because the driver ledger's
two bounded fleet-release reads still required a capability split.

Implemented driver recovery-read capability slice (2026-08-25): migration
`0045_driver_recovery_read_capabilities` moves the normal fleet release and
forward-reconciliation recovery joins behind distinct fixed-search-path
`SECURITY DEFINER` functions. The first validates the complete live release
lease and global resource fence; the second validates the current observation
claim and quarantined original release identity. Both are fail-closed and
bounded to 501 rows, and neither is executable by PUBLIC. Tenant-scoped driver
recovery reads and updates intentionally retain direct access pending the final
forced-RLS policy matrix review; this migration does not claim that parent-table
RLS is complete.

Implemented recovery-point policy slice (2026-08-25): migration
`0046_recovery_point_tenant_rls` enables and forces RLS on the recovery parent
with a command-specific role matrix. Platform API status and backup-scheduler
discovery remain explicitly fleet-readable. Tenant API SELECT/INSERT,
lifecycle SELECT/UPDATE, scheduler INSERT, and driver SELECT/UPDATE require the
fail-closed transaction-local workshop identity; release-driver fleet reads
continue through the exact capabilities introduced in migration 0045. The
lifecycle worker loses unused direct INSERT/DELETE privileges and no runtime
role receives a DELETE policy. Live production-role tests cover catalog flags,
policy metadata, ACLs, same-workshop success, and missing, malformed, and cross-
workshop denial.

Implemented membership policy slice (2026-08-25): migration
`0047_membership_tenant_rls` enables and forces RLS on membership authority.
The platform API keeps only fleet reporting SELECT; its initial-owner and
invitation-acceptance writes are exact `SECURITY DEFINER` capabilities bound to
admitted commands and authoritative workshop or invitation state. Tenant API
SELECT/UPDATE and all reviewed worker, scheduler, privacy-driver reads require
the fail-closed transaction-local workshop identity. Backup fleet discovery is
a bounded scheduler-only projection, and privacy subject-workshop expansion is
bound to the exact in-flight privacy lease. Invoice and inventory workers lose
unused SELECT, no runtime role has direct INSERT/DELETE, and the live role
matrix verifies both capabilities and cross-tenant denial.

Implemented invitation policy slice (2026-08-25): migration
`0048_invitation_tenant_rls` enables and forces RLS on invitation capability
state. Tenant API reads and mutations and email-worker reads require the
fail-closed transaction-local workshop identity. The platform API has no direct
table privileges: verified-token bootstrap uses an exact live invitation lock,
and authenticated resend or revocation discovery requires active owner or
studio-manager authority. Privacy retention remains function-only under its
existing operation-lease fence. Live role tests verify scoped access, token
generation and expiry fencing, management authorization, and stale direct-grant
removal.

Implemented outbox policy slice (2026-08-25): migration
`0049_outbox_tenant_rls` enables and forces RLS on the non-null workshop-owned
mail `outbox`. Platform reporting keeps fleet SELECT only; tenant and
reconciliation producers and the email worker use the fail-closed
transaction-local workshop identity. Authenticated provider evidence is applied
by one exact, replay-safe `SECURITY DEFINER` capability that owns the event,
delivery-state, branded-domain test, and suppression transaction. The privacy
worker loses direct table authority and continues bounded deletion only through
the existing leased retention capability. The live role matrix verifies scoped
producer and worker behavior plus provider-event replay and conflict fencing.

Implemented driver admission slice (2026-08-22): duplicate lifecycle payloads
no longer carry a PostgreSQL target reference. Before maintenance or runtime
effects, the driver derives the target from same-workshop primary/duplicate
ledger ownership and passes only that persisted identifier to restore and
carrier neutralization. Migration `0009_driver_idempotency_scope` replaces the
global driver key with `UNIQUE NULLS NOT DISTINCT (workshop_id, action,
idempotency_key)`, preserves one deliberate global release namespace, makes
admission concurrency-safe with insert-first conflict handling, and narrows the
driver role to identity-column inserts and outcome-column updates.

Implemented driver tenant-ledger slice (2026-08-22): `DriverState` now exposes
an explicit `TenantStore` capability for workshop-owned recovery, lifecycle,
and release-adoption reads and mutations. These paths use composite
`(resource_id, workshop_id)` identity in short transactions that finish before
Docker or PostgreSQL effects. Provisioning derives the privileged PostgreSQL
database name from the scoped ledger instead of accepting a caller-supplied
name. Startup repair remains an explicit fleet capability, but its scan is
bounded and its marker clear is a composite compare-and-set. Cross-workshop
database and duplicate-target tests, source-level architecture gates, and
production-role grant tests protect the boundary. This narrows the remaining
review surface; it does not make the affected tables RLS-ready while privacy,
release fleet coordination, and other machine workflows remain mixed-scope.

Implemented release finalization fencing slice (2026-08-22): fleet activation
and terminal failure now acquire locks in the same operation-lease, application-
release, fleet-run order. Both paths are fenced to the current durable worker
lease and attempt; an unknown outcome is never collapsed into terminal failure.
Finalization requires exact compare-and-set success for both the run and release,
the immutable fleet generation and canonical tenant snapshot, the exact prepared
adoption identities, a completed activation intent, and runtime evidence bound
to the admitted manifest. API and driver fleet discovery is bounded to 500
tenants until chunked adoption exists, and the driver rejects snapshot drift
before external effects. This removes one worker/failure split-brain path.

Implemented release driver-replica lease slice (2026-08-22): migration
`0010_release_driver_lease` adds a singleton database lease for the shared Odoo
runtime, monotonic fencing, and function-only admission, renewal, and
finalization. Admission proves the exact current release-worker operation
attempt; per-tenant and fleet-wide effect boundaries renew the lease; fleet
runs, activation intents, receipts, and final worker evidence carry the same
fence. A concurrent distinct target is rejected while held. Expiry or an
unknown effect outcome atomically quarantines the resource and rejects stale
renewal/finalization instead of stealing it. The process-local mutex remains an
optimization only. Because Docker, filesystem, route, and PostgreSQL effects do
not themselves enforce the token, quarantine has no automatic clear path:
reconciliation must first terminate or prove quiescent the prior executor and
observe authoritative runtime, route, database, and intent state. Migration
`0023_fleet_release_forward_reconciliation` provides that durable claim and
finalization boundary for protocol-v1 fleet executors. It persists the original
host instance, driver operation, fence, fleet run, action and gateway identity;
records expired claim attempts; rejects stale completion tokens; and accepts
only a closed, forward-only proof of executor quiescence, candidate runtime,
loaded gateway identity, target database access and old-runtime retirement.
Only that proof may acknowledge the exact activation intent, convert the
original receipt to success and release quarantine. Inconclusive observations
remain quarantined, while legacy NULL protocol identities cannot be adopted.
No rollback, route replay, old-runtime grant or failure transition is exposed.
Phase-boundary renewal is
reinforced by a structured 20-second heartbeat; heartbeat loss cancels the
in-flight future and enters the same outcome-unknown quarantine path.
The migration also refuses any historical successful release receipt that
lacks operation/fence evidence; deployment requires explicit reconciliation of
that state rather than fabricating authority or replaying unfenced evidence.

Implemented bounded initial-release reconciliation slice (2026-08-22):
migration `0018_initial_release_reconciliation` adds function-only, expiring
observation claims for an outcome-unknown initial preparation. Admission
re-proves the current release-worker attempt, original operation/fence, prepared
slot evidence, and an entirely empty fleet. The driver performs only a fresh
read-only Docker inspection; an exact running image, config digest, and
read-only extension mount atomically converts the original receipt to success
and releases quarantine only after re-authenticating the current upstream lease
and locking/rechecking the empty-fleet predicate through commit. Inconclusive inspection is durable and leaves the
resource quarantined. Fleet activation is excluded: replaying or clearing it
without observing and compensating gateway publication, tenant grants, and
old-runtime shutdown across the fence would be unsafe.

Implemented webshop-domain claim and tenant-capability slice (2026-08-22):
migration `0011_webshop_domain_reconciliation` admits a bounded set with
`FOR UPDATE SKIP LOCKED`, inserts each durable command, and binds it back to the
same workshop/domain in one transaction. A composite foreign key prevents an
operation from being attached across workshops. The function has a fixed
search path, no PUBLIC execute privilege, and is executable only by the
reconciliation identity; concurrent and production-login tests cover those
properties. Post-lease reconciliation uses only `TenantStore`, coherent
repeatable-read snapshots, and exact live-attempt compare-and-set mutations.
No database transaction spans provider, driver, or Odoo I/O. Driver calls carry
and revalidate the upstream attempt/owner immediately before effects, and
ambiguous provider sends retain unknown-outcome semantics. This slice does not
enable RLS or remove the reconciliation role's existing fleet-wide SELECT and
UPDATE grants, so it is not database-enforced tenant isolation. Full-workshop
route documents also need a monotonic database generation and cross-replica
driver fence before concurrent domain/module/lifecycle projection is safe;
provider deletion needs authoritative reconciliation before terminal repair.

Implemented webshop-domain RLS compatibility preparation (2026-08-22): every
application route-projection read now receives `WorkshopTransaction`, including
platform/internal admission snapshots and Paperless enablement before driver
I/O, and the workshop dashboard no longer reads domains through the mixed API
pool. Migration `0021_webshop_domain_claim_compatibility` replaces the API's
inline cross-workshop `ON CONFLICT` mutation with a fixed-path, tenant-context
and active-manager checked claim capability. It preserves the deployed global
hostname constraint and disconnected-row reclaim during rolling deployment;
provider-deletion evidence prevents unsafe ownership reuse. The later RLS
migration must replace global uniqueness with live-row uniqueness and redefine
the stable capability to insert a fresh row before it enables and forces the
policy. This preparation deliberately does not claim RLS enforcement.

Implemented privacy export capability slice (2026-08-22): an access or
portability worker accepts only a request whose `operation_id` and
`subject_user_id` match the current leased operation. A short fleet transaction
captures subject, identity, history, processor-task, and bounded workshop
identity data; every workshop membership is then resolved through its own
`TenantStore` transaction. All transactions finish before processor HTTP,
encryption, or artifact writes. After durable export publication, processor
evidence and request completion are committed together only while the same
operation lease and attempt remain current. The API validates explicit workshop
scope through `TenantStore`, and the deployment driver similarly commits its
tenant snapshot before secret reads and processor calls. Retention, erasure,
and artifact cleanup remain separate mixed-scope reviews; opportunistic file
cleanup is ordered after request/lease validation and bounded per pass, but it
does not yet have a database cleanup lease. This slice does not declare their
tables RLS-ready.

This is a candidate set, not an authorization to enable policies. Before each
table is migrated, every API, worker, scheduler, driver, trigger, foreign-key
path, and security-definer function touching it must appear in the role/workflow
matrix. Indirect children such as recovery components need a policy joined
through their owning recovery point. Mixed-scope tables such as `operations`,
privacy records, users, audit events, and release coordination remain
outside the first wave until their global/null-workshop semantics are modeled.

## Verification gates

Database-enforced tenant isolation may be claimed only when all of these run in
CI against disposable PostgreSQL using the real migrations and runtime roles:

1. connection reuse: tenant A commits, the same physical connection is reused
   without context and cannot see A, then tenant B sees only B;
2. rollback and error paths: context disappears after rollback and after an
   aborted transaction;
3. direct SQL: every runtime role attempts cross-tenant `SELECT`, `INSERT`,
   `UPDATE`, and `DELETE` on every protected table, with an explicit expected
   allow/deny reason;
4. worker workflows: fleet lease/claim succeeds, tenant work is constrained to
   the leased workshop, and global operation kinds are separately covered;
5. platform/internal workflows: the distinct role can perform each documented
   cross-workshop operation while the tenant role cannot assume that role;
6. migration ownership: owner and runtime `BYPASSRLS`/membership attributes and
   `relrowsecurity`/`relforcerowsecurity` flags match the manifest;
7. application tests: representative API and worker operations succeed through
   their production pool type, not an owner connection.

`CONTROL_TEST_DATABASE_URL` is insufficient for role creation and ownership
checks. The full gate requires a disposable `CONTROL_TEST_ADMIN_URL` with
`CREATEDB` and `CREATEROLE` (normally a PostgreSQL 17 test instance). Until that
gate is available and green, source scanning and the characterization test must
not be described as database-enforced isolation.

## Consequences

- Immediate work remains compatible with fleet workers and strengthens query
  construction without pretending table ACLs are tenant isolation.
- RLS rollout requires explicit tenant/platform pool types and more transaction
  boundaries; this cost is intentional and visible.
- Platform and recovery capabilities receive smaller, reviewable database
  surfaces instead of blanket RLS bypass.
- Migrations 0005 and 0016 implement the first reviewed slices: the API has a distinct
  `control_tenant_api` pool, workshop mutations install transaction-local
  context, and `ownership_transfers` uses forced RLS, while scoped lifecycle
  and driver transactions protect recovery components. The remaining candidates
  stay deferred until their API and worker paths satisfy the same executable
  role/workflow proof.
- Durable operations now fail closed on kind/queue/workshop-scope mismatch, and
  membership execution uses transaction-scoped workshop context after a fleet
  lease. Other worker queues still require the same migration before their
  tenant tables can be considered for RLS.
