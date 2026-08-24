# Backup and restore contract

The control UI replaces Odoo's native database manager. Only a workshop owner
can request lifecycle actions, and callers never submit or see a physical
database name, filesystem path, bucket name, or object key. The deployment
driver resolves an authenticated recovery ID against control-plane state. A
download request returns only a ten-minute, read-only signed URL for the
verified portable archive.

The API supports:

- A local snapshot for fast environment-local rollback.
- An encrypted, remotely verified portable backup.
- Restore from a ready, unexpired and verified recovery point.
- An isolated Odoo duplicate with no hostname or public route.

Requests are serialized per workshop, idempotent, queued and audited. During a
lifecycle operation the gateway returns maintenance responses only for the
target workshop, the invoice worker stops admitting work for its database, and
the driver drains active invoice capture. The shared Odoo process remains
available to unrelated workshops.

## Recovery boundary

Every version-2 recovery set contains the Odoo PostgreSQL database and matching
filestore. When `documents` was active at creation time it also contains the
Paperless PostgreSQL database and its `data`, `media`, and `consume` volumes.
The driver stops that workshop's Paperless container while capturing the set.
Redis is deliberately excluded because it is derived queue/cache state.

The component scope is immutable. A full restore requires the current workshop
to have the same Paperless scope; restore never silently activates, disables,
or wipes an optional service. Only the complete
`mb-workshop-recovery-v2` format is accepted; recovery artifacts from
the disposable pre-release schema epoch are not retained or restorable.

The manifest records component checksums, source release, and exact Paperless
image. A Paperless restore is rejected until the recorded image version is
configured, so schema migration happens as a separate upgrade after recovery.

Control-plane and Rauthy data belong to platform PostgreSQL PITR, not a
selective workshop restore. Azure Business is an external integration and has
no local dataset in the recovery set. Secret values are never backed up;
infrastructure restores secret references from the approved secret manager.

## Portable backup

A snapshot is an environment-local recovery point optimized for quick rollback.
It depends on the current deployment and is not downloadable. A backup is the
portable form: the server-side lifecycle worker creates one
`mb-workshop-backup.tar` containing the encrypted components, encrypted
manifest and completion marker, uploads it to S3, and verifies it before making
the Download action available. Requesting a download never sends S3 credentials
to the API or browser; the isolated driver signs the verified archive for ten
minutes using its read-only identity.

The backup helper streams PostgreSQL dumps and tar archives through zstd and age
before writing a local ciphertext staging object. It then uses AWS CLI managed
multipart transfers to the environment's private Scaleway S3 bucket. Every
ciphertext is read back and SHA-256 verified before `complete.json` is uploaded
last. An incomplete prefix has no commit marker and is never restorable.

The routine writer uses a public age recipient and S3 credentials without
delete or bucket-administration permissions. Restore uses a separate read
credential and the age identity. Production objects are versioned and held
under 35-day governance Object Lock; local ciphertext staging is removed only
after remote verification succeeds.

For a key rotation, generate and escrow the new age identity outside the
runtime, add both old and new identities to the isolated restore identity file,
then deploy the new public recipient and key ID to the writer. Keep every old
private identity until its last recovery set has expired and a rehearsal using
the new identity has succeeded. Only then remove the old identity. Never put a
private identity or S3 secret in control-plane PostgreSQL, an operation payload,
an image layer, or an application-worker environment.

Production restore credentials are deliberately time-bounded. Add a temporary
infrastructure `reader_grants` entry for the selected immutable recovery prefix,
inject that identity into the driver for the maintenance window, perform the
restore, then remove the grant and secret. The routine writer is
not a substitute live-restore credential. Automated read-only rehearsals use
the writer's existing read-back permission because they are part of backup
verification and never cut over data.

`control-backup-scheduler` queues one portable backup for every due workshop in
each 24-hour window. Owners can create additional snapshots or backups before
upgrades and destructive maintenance. The same scheduler rehearses the newest
verified portable backup at least monthly by downloading, authenticating,
decrypting and restoring its database dumps into disposable databases. The
result is persisted in `workshop_recovery_rehearsals` and the live workshop is
never modified.

Fleet discovery is bounded, but each selected recovery is claimed in a short
workshop-scoped transaction before the driver request. The transaction is
committed before network I/O. A claim carries an opaque fencing token, a
20-minute lease, and a durable maximum of six attempts. Expired leases can be
reclaimed; only the current token may finalize a result. Transport failures,
HTTP 408/429, and server failures receive bounded exponential retry delays;
other driver rejections are terminal. Result and audit-event persistence commit
atomically in a fresh workshop transaction.

The scheduler parses its complete immutable configuration before telemetry,
PostgreSQL, or deployment-driver initialization. Scheduling is disabled by
default (`CONTROL_BACKUP_SCHEDULER_ENABLED=false`) and its poll interval defaults
to 3,600 seconds. Explicit enablement accepts only `true` or `false`; an explicit
interval must be an integer between 60 and 86,400 seconds. Database and driver
URLs, the release identity, and the optional absolute Unix-socket path are
validated at that same startup boundary, so malformed tuning never silently
falls back.

Lifecycle progress is persisted on the operation as phase, message and
percentage. The control UI refreshes active operations once per second, so
capture, encryption, packaging, S3 upload and verification remain visible after
a page reload. Percentages are phase-based because the helper intentionally does
not expose S3 transfer internals or credentials to application workers.

## Restore

Every restore first creates and remotely verifies a complete S3 safety backup.
The selected recovery is then downloaded with reader credentials. The driver
validates the commit marker, authenticates and decrypts the manifest, verifies
every ciphertext and plaintext checksum, and fully decrypts and
compression-tests all components before replacing live data.

Odoo and Paperless databases and files are cut over while the workshop remains
in maintenance. If a failure happens after replacement begins, the driver
automatically restores the verified safety backup. The workshop route is not
reopened until the selected restore or rollback finishes. A failed rollback
leaves the database in `restoring` state and the crash-safe maintenance route in
place for operator intervention; driver startup does not reopen such a route.

Automated validation checks Odoo and Paperless schema presence, Paperless
document checksum metadata, and every Odoo invoice-capture link to a restored
Paperless document ID. It runs against disposable databases during preflight
and again against the live targets before routes reopen. Paperless container
health is also required.

## Operations

Alert on failed recovery rows, backups older than 24 hours, and failed or
missing rehearsals older than 30 days. Scheduler and driver failures are emitted
as structured error logs; `workshop_recovery_points.verification_state` and
`workshop_recovery_rehearsals.state` are the durable monitoring sources. Prefixes
without `complete.json` are incomplete and can be investigated but never
restored. Quarterly disaster-recovery exercises must also test the separate
platform PostgreSQL PITR procedure; its proposed 15-minute RPO and four-hour RTO
remain subject to business-owner approval.

Run `tests/backup-s3-smoke.sh` after changing the helper image or S3 client. It
uses an isolated MinIO network to exercise encrypted upload/download and proves
that a wrong age key and modified ciphertext are rejected.

A restore is successful only when:

1. Odoo opens the company and attachments with the restored filestore.
2. When Documents is enabled, Paperless returns the same document IDs and
   original SHA-256 digests.
3. Service endpoints remain valid and membership reconciliation reaches every
   desired epoch.
4. Replaying the last invoice operation creates no duplicate capture or bill.
5. A Rauthy subject can sign in to the control UI, Odoo, and enabled Paperless,
   while a subject from another workshop is denied.

The remaining rehearsal matrix is the P2 recovery gate in
[CONTROL-PLANE-ROADMAP.md](CONTROL-PLANE-ROADMAP.md).
