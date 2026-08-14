# ADR 0001: Shared Odoo runtime with database-per-workshop isolation

Status: accepted

Each workshop owns one opaque PostgreSQL database while a release-homogeneous
Odoo runtime serves multiple workshops. The gateway, not client input, maps an
exact host to an opaque database identifier and replaces database-selection
headers. Database listing and management endpoints remain disabled.

The deployment driver generates a distinct high-entropy bridge credential for
each workshop. Only its SHA-256 verifier is stored in that workshop's Odoo
database; the plaintext is delivered through the worker-facing tenant secret
volume. The shared bootstrap credential is accepted only while the database has
no tenant verifier, after which every bridge request is authenticated against
the selected database. Rotating or compromising one workshop credential
therefore does not authorize another database.

Upgrade from the former shared-token release is deliberately two-phase. The
module migration seeds the existing verifier so candidate health checks do not
fail mid-fleet; the first idempotent reconciliation then rotates that workshop
to its random token. The release is not production-approved until reconciliation
has completed for every routed workshop and the two-workshop black-box gate
rejects cross-use.

This reduces idle runtime cost without weakening the data boundary. It requires
negative routing tests and prevents a runtime switch until every routed tenant
is compatible. A second runtime cluster is introduced only when placement,
availability or release-isolation requirements justify it.
