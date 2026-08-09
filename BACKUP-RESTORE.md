# Backup and restore contract

The control UI deliberately replaces Odoo's native database manager. Only a
workshop owner can request lifecycle actions, and callers never submit or see a
physical database name. The public route is `<workshop-slug>.<tenant-domain>`;
the physical identifier is an unrelated `mb_<opaque UUID>`.

The API supports:

- a snapshot for fast environment-local rollback;
- a portable backup for export/long-term retention;
- restore from a ready recovery point, always preceded by a safety snapshot;
- an isolated duplicate with no hostname and no public route.

Requests are serialized per workshop, idempotent, queued, audited, and exposed
through operation state. The deployment driver returns only opaque storage
references and byte counts. It must quiesce the tenant and handle the Odoo
PostgreSQL database and filestore together; the development fixture is a
contract simulator and is not a backup engine.

The Docker driver's owner-facing database actions create an Odoo recovery set:
the selected Odoo PostgreSQL database and its matching filestore namespace.
This is the implemented replacement for Odoo's native database manager; it is
not presented as an encrypted whole-tenant disaster-recovery export.

The production disaster-recovery contract is a separate encrypted recovery set
per workshop: the Odoo PostgreSQL database and filestore; when the `documents`
module is enabled, the Paperless PostgreSQL database and media/data; plus the
control rows for the workshop, memberships, modules, external identities,
service instances, entitlements, operations, usage, and audit.
`makersbrain-infra` owns that Phase-4 orchestration and encryption. Secret
values are never part of either set; infrastructure restores their references
from its secret manager.

Before an Odoo or enabled Paperless upgrade, stop admission for that tenant,
let active operations finish, record the image digests, and take all members of
the set under one recovery-set identifier. Keep the previous images until the
restore drill passes.

A restore is successful only when:

1. Odoo opens the company and its attachments with the restored filestore.
2. When Documents is enabled, Paperless returns the same document ids and
   SHA-256 original digests.
3. Control-plane service instances point to the restored endpoints and a
   reconciliation reaches every desired membership epoch.
4. Replaying the last invoice operation creates no duplicate capture or bill.
5. A Rauthy subject can sign in to the control UI and Odoo, plus Paperless when
   enabled, while a subject from another workshop is denied.

Monitor backup age, queue depth, oldest lease, dead letters, membership drift,
service health, and Azure page usage. Alert before tenant deletion, entitlement
suspension, or a backup misses two scheduled intervals.
