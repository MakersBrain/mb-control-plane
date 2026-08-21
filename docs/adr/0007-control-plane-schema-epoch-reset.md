# ADR 0007: Reset the unreleased control-plane schema epoch

Status: accepted

The control plane has not been deployed to production, and no existing control
or tenant data must be migrated or retained. Maintaining upgrade code for the
development-only schema, secret layouts, recovery format, capability registry,
and frozen OpenAPI baseline would make the first supported release harder to
operate without protecting a real installation.

Replace the accumulated control PostgreSQL migrations with one curated base
migration. Renumber the current capability registry as version 1 of the new
epoch and remove development-era compatibility adapters. Existing databases
are intentionally incompatible with the new migration set and must fail closed;
the SQLx ledger must never be edited to cross the epoch boundary.

The reset boundary is the complete environment, not only the control database.
Any local or non-production topology from the old epoch is disposable and must
be destroyed before starting the new code. The retained 30-day workshop
deletion workflow is a product feature and is not suitable for this reset.

A blank control database has no active application release. The release
workflow therefore supports a tightly constrained empty-fleet activation for
the first verified and prepared release. It is unavailable after a release or
tenant exists; ordinary tenant release adoption remains unchanged.

There is no data rollback across this decision. Before resetting an
environment, code may be reverted normally. Afterward, rollback means destroying
the disposable topology and creating another blank topology using one coherent
code and schema epoch.
