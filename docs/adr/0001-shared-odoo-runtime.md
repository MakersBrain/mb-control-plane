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

The development-only shared-token transition described by the original version
of this ADR was retired by ADR 0007 before the first production release. Fresh
provisioning installs the tenant verifier during the single authenticated
bootstrap request, and the two-workshop black-box gate must reject cross-use.

This reduces idle runtime cost without weakening the data boundary. It requires
negative routing tests and prevents a runtime switch until every routed tenant
is compatible. A second runtime cluster is introduced only when placement,
availability or release-isolation requirements justify it.
