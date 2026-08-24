# Control-plane hardening baseline and tenant-isolation threat model

Status: active review evidence

Base revision: `f991469031be114d2f3e9b8385db3cb1e00d696d`
(`origin/main` when the hardening branch was reviewed)

## Baseline results

The base revision was reconstructed in a clean temporary checkout on
2026-08-23. `cargo fmt --check` passed. `cargo test --locked` passed with 156
tests and 2 environment-dependent tests ignored; all binary and documentation
test targets also passed, while the PostgreSQL and Odoo suites remained ignored
without their disposable services. The frontend check could not run from the
archive because its untracked `node_modules` installation is not part of Git.
There were no observed Rust failures to preserve as expected failures.

The branch route inventory is checked in as
[`control-plane-route-security-inventory.tsv`](control-plane-route-security-inventory.tsv).
It is generated from the same public and internal route registries that build
the Axum routers. A unit gate compares every method, path, access policy and
handler symbol with that file, so a route change cannot silently leave the
inventory stale.

## Protected assets and identities

The protected boundary is every workshop-owned row, durable operation,
provider credential, external effect, generated route, Odoo database and
Paperless service. Human principals, platform principals and machine identities
are separate authority domains. A workshop UUID supplied by a caller is routing
input, not authority.

Tests use two distinct workshops, principals with viewer, studio-manager and
owner roles, and child resources owned by each workshop. Resource-derived routes
must recover the resource's workshop before authorizing it; path-scoped routes
must use the middleware-issued `WorkshopScope`.

## Threats and required guarantees

### Missing membership check

Every `/v1/workshops/{id}` method must declare `Workshop(...)` access in the
route registry. Middleware authenticates, loads the exact active membership and
checks the declared permission before the real handler runs. Tests issue denied
requests through the production route registry, not a substitute probe router.

### Authorize workshop A, query workshop B

Handlers consume the validated workshop ID from `WorkshopScope`. Tenant SQL runs
through a transaction-local `TenantStore` context, and child predicates include
both the resource ID and workshop ID. Tests deliberately combine workshop A's
authority with workshop B's resource IDs.

### Unscoped list or mutation

Static source gates reject known unscoped child-table mutations, while
PostgreSQL tests exercise runtime-role reads and writes. The static gate is only
a regression aid; forced RLS or function-only capabilities remain the database
authority for tables marked enforced in ADR 0008.

### Child resource belonging to another workshop

The public result is not-found, never a distinguishable forbidden response.
Rejected mutations must leave database state unchanged and must not invoke an
external adapter. Handler-level PostgreSQL tests cover each child-resource
family as it is migrated into the database isolation matrix.

### Stale role or authority epoch

Middleware authorization is sufficient only for reads. A mutation re-locks the
membership or platform grant inside its transaction and rechecks the exact role,
permission and authority epoch before command admission or external effects.

### Workers and internal APIs

Workers authenticate the exact queue, operation attempt, lease owner, expiry
and workshop execution scope before dispatch. Internal routes use the separately
inventoried machine credential domains and do not apply human membership rules.
Body-scoped carrier-secret resolution is the sole documented middleware
exception and authenticates before database access.

## HTTP and database guarantees

HTTP authorization guarantees that unauthorized handlers are not entered and
that an entered workshop handler receives validated authority context. It does
not by itself prove SQL tenant isolation. Database isolation separately requires
workshop predicates, transaction-local capabilities, least-privilege runtime
roles and direct cross-tenant tests. Database-enforced isolation is claimed only
for the tables identified as enforced by ADR 0008 and its live PostgreSQL gate.
