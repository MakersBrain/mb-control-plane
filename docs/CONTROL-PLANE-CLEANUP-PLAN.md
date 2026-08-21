# Control-plane legacy cleanup and schema reset plan

Status: implemented; destructive environment reset and live qualification pending
Date: 2026-08-21
Scope: `mb-control-plane` and its current external contracts

## 1. Objective

Remove legacy and backward-compatibility implementation paths from the control
plane and replace the accumulated PostgreSQL migration history with one fresh
base migration.

This is a hard schema-epoch reset for software that has not been deployed to
production. No existing control-plane or tenant data must be migrated or
retained. Existing databases and all resources created by this control plane
will be destroyed and recreated; upgrading an existing installation is
explicitly unsupported.

Versioned names such as `/v1`, `/internal/v1`, and `/mb_control/v1` are the
current public and bridge protocols, not compatibility shims. They remain in
scope as current interfaces unless a separate coordinated API redesign is
approved across the web application, infrastructure, Paperless hook, and
`mb-odoo-addons`.

## 2. Destructive reset boundary

A control-database-only reset would leave untracked development resources. The
database owns the identities of external resources including:

- Odoo and Paperless PostgreSQL databases;
- Paperless containers and persistent volumes;
- Redis ACL users;
- Rauthy clients;
- gateway routes;
- tenant and runtime secret subpaths;
- recovery sets and privacy-export artifacts.

The existing workshop-deletion lifecycle is not a reset mechanism: it creates a
final recovery set and deliberately retains a quarantined tenant for 30 days.
Do not use it as preparation for this reset. Destroy the complete
local/non-production topology, including databases, containers, volumes, Redis
ACL state, identity clients, routes, secrets, recovery objects, and privacy
artifacts. The new control plane must not start while any resource from the old
epoch remains.

Required preparation and execution controls:

1. Confirm that the selected environment is non-production and disposable.
2. Stop the API, workers, schedulers, and provisioning/deployment driver.
3. Destroy the complete topology using the environment-owned reset procedure.
4. Verify that no old database, volume, secret subtree, route, identity client,
   Redis ACL user, or recovery object remains.
5. Record the new schema epoch and unsupported-upgrade boundary in an ADR.

The implementation must never edit the SQLx ledger or mark the new baseline as
applied to an old database.

## 3. Fresh database baseline

Replace the 39 existing migration files, currently about 2,400 lines, with:

```text
migrations/0001_control_plane_base.sql
```

The baseline must directly declare the final schema:

- schemas, tables, columns, constraints, and indexes;
- views, functions, and triggers;
- fixed security-definer search paths and function privileges;
- comments that express current invariants;
- final grants and default privileges for every runtime database role.

The baseline must not contain historical operations such as schema renames,
constraint replacement, data backfills, legacy redaction, transition repair,
or old-format conversion. It must not seed capability-registry v1.

Use the current migrations and application queries as implementation references
while curating the baseline; do not preserve historical operations merely to
make the new schema catalog identical to an old installation. The acceptance
contract is the current application behavior, invariants, and least-privilege
role matrix on a newly created PostgreSQL 17 database.

Update all schema identifiers together:

- set `EMBEDDED_SCHEMA_RELEASE` to `0001_control_plane_base`;
- update `schema_release` in `deploy/release-contract.json`;
- replace the stale schema compatibility range with the new baseline contract;
- update validation scripts, release metadata, tests, and documentation.

Changing the SQLx version-1 checksum is intentional: old databases must fail
closed and require recreation.

Required database gates:

- a blank PostgreSQL 17 database migrates successfully from the new baseline;
- all PostgreSQL integration and runtime-role matrix tests pass;
- functions with elevated privileges have fixed search paths and explicit
  execute grants;
- attempting to run the new migrator against a database with the old SQLx
  ledger fails closed with no ledger modification.

## 4. Capability-registry reset

1. Delete `deploy/capability-registry-v1.json`.
2. Rename the current registry to `deploy/capability-registry.json`.
3. Treat its content as version 1 of the fresh control-plane epoch.
4. Recalculate its digest and update the release contract and Rust constant.
5. Seed only the current registry through `sync_capability_registry()` after
   the base migration.
6. Remove migration-era registry inserts and tests that expect the historical
   13-entry registry.
7. Remove hard-coded registry selection from tenant provisioning. In
   `src/worker.rs`, provisioning currently inserts `registry_version=1`; it
   must resolve and persist the registry declared by the active application
   release.

The registry tables and immutable version model remain because they are current
release-integrity mechanisms, not compatibility scaffolding.

### 4.1 First application-release bootstrap

A fresh database contains no active application release. Tenant provisioning
requires an active release, while the current adoption path refuses adoption
when no tenant database exists. Remove this bootstrap deadlock.

Add a dedicated initial-release activation path that:

1. is allowed only when there are no workshops, tenant databases, tenant release
   adoptions, or active application release;
2. requires a normally published, verified, and prepared release whose declared
   capability registry matches the embedded active registry;
3. verifies the prepared runtime slot and all ordinary release-integrity
   evidence;
4. atomically marks that release and runtime slot active, with an immutable
   audit record;
5. cannot be used once the first tenant or active release exists.

Do not seed a synthetic application release in the base migration. Test the
empty-fleet activation path, its replay/idempotency behavior, and every refusal
condition. Fresh tenant provisioning must then resolve the registry version
from this active release rather than inserting a literal version.

## 5. Runtime compatibility removal

### 5.1 Local environment conversion

Delete the earlier plaintext-environment conversion path:

- `deploy/migrate-local-env-secrets.sh`;
- the legacy branch and message in `deploy/generate-local-config.sh`;
- legacy migration cases in `tools/test_local_secret_bootstrap.py`;
- related README and runbook instructions.

The supported local setup becomes a new bootstrap that creates the current
file-backed secret layout.

### 5.2 Deprecated inventory vision configuration

Remove the generic OpenAI-compatible legacy adapter and all associated
configuration:

- `BROKER_VISION_ENDPOINT`, `BROKER_VISION_KEY`, and `BROKER_VISION_MODEL`;
- `INVENTORY_VISION_ENDPOINT`, `INVENTORY_VISION_KEY`, and
  `INVENTORY_VISION_MODEL`;
- the `inventory_vision_key` Compose secret;
- legacy `OpenAiCompatible` aliases and selection branches;
- configuration-spec, release-contract, bootstrap, and test references.

The current explicitly selected OpenAI, Azure, Gemini, and Claude providers
remain.

### 5.3 Legacy recovery format

Remove support for `mb-odoo-recovery-v1`, including
`restore_legacy_recovery_set` and documentation promising that old local sets
remain restorable. Retain only the current complete workshop recovery format.

No old recovery set is retained or converted. The full-topology reset destroys
all recovery artifacts from the old epoch.

### 5.4 Transitional tenant credentials and secret layouts

Remove:

- fallback from tenant-scoped Odoo authentication to the shared bootstrap
  credential;
- conversion of a stored global bridge token into a tenant token;
- copying or cleanup of old `odoo-admin` and Paperless secret locations;
- tests and runbooks for the completed shared-token transition.

Fresh tenant provisioning must create only the current tenant-scoped secret
layout. Reconciliation must treat a missing or invalid tenant credential as an
error rather than attempting an upgrade.

### 5.5 Secret references

For secret-bearing settings, remove direct plaintext environment-value support
from `runtime_secret` and require an explicit `@/run/secrets/<leaf>` reference.
Non-secret settings must use ordinary configuration access rather than the
secret resolver.

`deploy/resolve-secret-env.sh` is currently used by the Odoo container. Replace
it with an image or startup configuration that consumes secret files natively
before deleting the adapter; deleting it first would break the current runtime.

### 5.6 Provider cryptography

The mail gateway currently ignores the envelope's `SignatureVersion` and always
uses an SNS RSA/SHA-1 algorithm marked for legacy use by the crypto library.
Implement explicit signature-version dispatch, RSA/SHA-256 verification for the
supported current version, and rejection of unknown versions. Verify a positive
delivery and negative signature/version cases in staging. Remove SHA-1 only if
the configured provider emits the SHA-256 version; otherwise retain it as a
documented current provider requirement rather than deleting working mail
authentication as part of this cleanup.

## 6. Public API compatibility cleanup

Remove the frozen released-baseline machinery:

- `deploy/openapi-v1-baseline.json`;
- `tools/check_openapi_compatibility.py`;
- `tools/test_openapi_compatibility.py`;
- `public_openapi_baseline` from the release contract and validator;
- CI steps that compare generated OpenAPI with the historical baseline.

Remove the synthetic bodyless `200`, `201`, and `202` response entries inserted
by `src/openapi.rs` solely for compatibility. Generated OpenAPI must describe
only responses the executable actually returns.

Keep the generated-client freshness check against the current executable
OpenAPI document.

Keep the real Odoo bridge integration lane. It verifies the current client
against the current external provider and detects cross-repository contract
drift; it does not exist to support an obsolete client.

## 7. Mechanisms explicitly retained

Do not remove the following as part of legacy cleanup:

- release adoption and directional database compatibility;
- fleet fencing and release rollback classification;
- recovery safety backups and restore validation;
- immutable audit and historical business records;
- ETags, compare-and-set writes, and idempotency handling;
- Docker and Podman runtime API-version selection;
- current API and bridge version prefixes;
- capability-registry versioning used by current immutable releases.

These mechanisms protect current and future operations. They are not adapters
for superseded control-plane behavior.

## 8. Contracts, CI, and documentation

Update every affected artifact in the same commit as the implementation change
that requires it, so every commit builds and passes its relevant gates:

- Dockerfile copy lists;
- `deploy/configuration-spec.json`;
- `deploy/release-contract.json`;
- application-release fixtures and generated release metadata;
- Compose environment variables, secrets, and mounts;
- contract and secret-canary tests;
- generated browser API client;
- architecture, roadmap, backup/restore, credential, and setup documentation;
- historical ADR status where an upgrade procedure is now retired.

Add a reset runbook that covers:

1. queue and API shutdown;
2. confirmation that the target is a disposable non-production environment;
3. complete topology destruction and absence verification;
4. database, volume, identity, route, and secret-layout recreation;
5. role bootstrap and the base migration;
6. control-plane startup and release publication/preflight;
7. empty-fleet activation of the first application release;
8. synthetic tenant reprovisioning;
9. isolation and recovery verification.

Search the repository for `legacy`, `deprecated`, `transitional`, `former`,
compatibility placeholders, every removed environment variable, and all old
migration names. Every remaining result must have an explicit current-purpose
justification.

## 9. Delivery sequence

Use four reviewable commits:

1. **Database baseline** — consolidate migrations, reset schema metadata and
   registry history, implement initial-release bootstrap, and update the
   Dockerfile, release contract, release fixtures, PostgreSQL tests, and role
   tests required by those changes.
2. **Runtime cleanup** — remove secret, recovery, credential, and vision
   compatibility paths together with their Compose wiring, configuration spec,
   release-contract declarations, image/startup files, tests, and documentation.
3. **Public API cleanup** — remove the OpenAPI baseline machinery and synthetic
   responses together with the corresponding CI checks, validator logic, and
   regenerated client.
4. **Reset operations** — add the reset runbook, ADR, final documentation, and
   repository-wide legacy audit.

Do not combine the destructive environment reset with the code-review commits.
Perform it only after the new images and base migration pass all gates.

## 10. Acceptance gates

The cleanup is complete only when:

- a blank PostgreSQL 17 database reaches the complete schema from the single
  migration;
- a second migration startup is a no-op;
- catalog assertions against the curated baseline manifest confirm the expected
  tables, columns, constraints, indexes, functions, triggers, grants, and
  default privileges; no comparison with or upgrade from an old database is
  required;
- runtime role-matrix tests pass;
- only the current capability registry is seeded and active;
- a verified release can be activated on an empty fleet, and the bootstrap path
  refuses use after the first release or tenant exists;
- tenant provisioning derives the registry from the active application
  release;
- Rust formatting, clippy, unit tests, and PostgreSQL integration tests pass;
- contract, configuration, secret-boundary, and Compose checks pass;
- the generated browser client matches executable OpenAPI;
- Odoo bridge integration passes;
- backup and restore pass using only the current recovery format;
- a complete fresh topology provisions two isolated synthetic workshops;
- cross-tenant token, hostname, database, Paperless, and Redis isolation gates
  pass;
- repository searches contain no unexplained legacy or deprecated path;
- attempting to start the new release against an old migration ledger fails
  clearly and does not mutate it.

## 11. Rollout and rollback

The code change can be reverted before the environment reset. There is no data
rollback and no pre-reset backup to restore. If the new epoch fails after the
reset, destroy its disposable topology and either recreate another blank new-
epoch topology after fixing the fault or recreate a blank topology with the
previous code and its original migration chain.

Never mix a database from one epoch with code from the other. Retain only reset
logs, release digests, and qualification evidence needed to diagnose the reset;
they are operational evidence, not an importable copy of the old environment.
