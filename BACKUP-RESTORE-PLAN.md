# Workshop Backup and Restore Plan

## Decision

A workshop recovery set covers Odoo and every stateful optional module that was
active when the recovery point was created. When the `documents` module is
active, Odoo and Paperless-ngx are backed up and restored as one consistency
boundary.

Azure Business is an external integration and has no local application data to
archive. Its configuration and credentials remain in the infrastructure secret
store and are not copied into workshop backups.

Per-workshop recovery sets are separate from platform disaster recovery. The
former provide selective workshop restoration; PostgreSQL WAL archiving and
PITR protect the complete control-plane and shared database platform.

## Recovery set format

Each recovery point uses an immutable S3 prefix:

```text
workshops/<workshop-id>/recovery/<recovery-id>/
├── odoo/database.dump.enc
├── odoo/filestore.tar.zst.enc
├── paperless/database.dump.enc       # present when documents was active
├── paperless/media.tar.zst.enc       # originals, archives, thumbnails
├── paperless/data.tar.zst.enc        # index and auxiliary data
├── paperless/consume.tar.zst.enc     # unprocessed uploads
├── manifest.json.enc
├── complete.json                     # component-set commit marker
└── makersbrain-workshop-backup.tar   # downloadable bundle of the files above
```

The manifest records:

- Recovery format version and recovery ID.
- Workshop ID without putting its mutable slug in object keys.
- Included components and module activation state.
- Odoo, Paperless and source release versions.
- Database identifiers, archive sizes and plaintext/ciphertext checksums.
- Encryption algorithm and key ID.
- Creation, verification and expiration timestamps.

Redis is excluded because it is queue/cache state, not the source of truth.
Paperless can recreate queued work and its search index from its PostgreSQL and
persistent file data.

Paperless recommends stopping active consumption and backing up its database and
persistent volumes. Its exporter is version-sensitive, so restoration must first
use the recorded Paperless image version before a separate application upgrade:
<https://docs.paperless-ngx.com/administration/>.

## Backup workflow

1. Create a recovery record in `creating` state and freeze its component scope.
2. Acquire the workshop lifecycle lock so activation, restore, deletion and
   invoice-transfer operations cannot overlap the backup.
3. Put the workshop's Odoo and `/docs` routes into maintenance mode.
4. Stop admission of new invoice/document operations and drain in-flight work.
5. Stop the workshop Paperless container when `documents` is active, then
   quiesce connections to the target Odoo database.
6. Stream PostgreSQL custom-format dumps and compressed file archives through
   authenticated client-side encryption directly into multipart S3 uploads.
   Plaintext backup artifacts must not be staged persistently on disk.
7. Upload the encrypted manifest after all components have succeeded.
8. Build the single-file portable archive on the server, upload every object,
   verify remote sizes and checksums, then upload `complete.json` last as the
   component-set commit marker.
9. Restart Paperless, release Odoo database quiescence, reopen routes and resume
   queued operations.
10. Mark the recovery point `ready` only after remote verification. Otherwise
    mark it `failed`; prefixes without a commit marker are never restorable.

Implemented: the driver drains only the target database and applies
per-workshop routing maintenance. The shared Odoo process remains available to
unrelated workshops.

## Restore workflow

1. Validate owner authorization, recovery readiness, retention state and module
   compatibility.
2. Acquire the workshop lifecycle lock.
3. Create and remotely verify a safety recovery set of the current workshop.
4. Enter maintenance mode, stop admission and drain in-flight operations.
5. Obtain temporary read credentials restricted to the chosen S3 prefix.
6. Download and authenticate all ciphertext, then decrypt it into protected
   temporary storage. Reject unexpected archive paths or identifiers.
7. Restore into temporary databases and directories first. Do not overwrite the
   live recovery target during download or validation.
8. Validate database connectivity, schema versions, file counts, document
   checksums and ownership.
9. Cut over the Odoo database/filestore and Paperless database/volumes as one
   maintenance operation.
10. Start Paperless with the recorded version, start Odoo access, and run any
    required Paperless index check.
11. Verify Odoo and Paperless health, document IDs, and Odoo-to-document links.
12. If validation fails, cut back to the safety recovery set before reopening
    the workshop.
13. Revoke restore credentials, securely clean plaintext temporary files, release
    the lifecycle lock and record an audit event.

Module-scope rules are strict:

- A recovery set containing Paperless requires `documents` to be active.
- A recovery set without Paperless cannot be used as a full restore after the
  workshop has accumulated Paperless data.
- An Odoo-only restore may be offered as an explicit advanced operation, but it
  must warn that Paperless and its Odoo links are not rolled back.
- Restore does not silently activate or deactivate modules.

## Infrastructure work

Implement the planned backup resources in `makersbrain-infra`:

- A private Scaleway S3 bucket per environment in `fr-par`.
- Versioning and production Object Lock in governance mode for 35 days.
- Server-side encryption as defense in depth, in addition to mandatory
  client-side encryption.
- A backup-writer identity permitted to create, read and verify objects but not
  delete them or administer the bucket.
- Temporary, prefix-scoped restore-reader credentials.
- Multipart upload cleanup, access logging, deletion protection, monitoring and
  alerts.
- Encryption keys held outside Scaleway credentials. Prefer an `age` public
  recipient for the writer and an independently escrowed private restore key.
- Key IDs and a documented rotation procedure that retains old restore keys for
  at least the complete backup retention period.

The control-plane API and ordinary workers must never receive S3 or decryption
credentials. A narrowly scoped backup agent performs data access, encryption and
object-store operations; the control plane only orchestrates it by recovery ID.

## Control-plane changes

Generalize the current Odoo-only recovery model:

- Replace or migrate `odoo_recovery_points` to `workshop_recovery_points`.
- Store format version, component scope, storage location, opaque S3 prefix,
  encryption key ID, source release, Paperless version, verification state,
  `verified_at`, and `expires_at`.
- Add component records containing object type, size, digest and upload state.
- Keep `makersbrain-odoo-recovery-v1` rows readable as legacy Odoo-only points.
- Send only recovery IDs in operation payloads. Never accept arbitrary bucket
  names, URLs, filesystem paths or object keys from a user request.
- Use the same component format for local snapshots and remote backups, so an
  active Paperless instance cannot be omitted accidentally.

## Retention and scheduling

Initial policy:

- Nightly full workshop recovery set.
- Additional recovery point before restore, upgrade or destructive maintenance.
- 35-day immutable production retention.
- Incomplete multipart uploads cleaned automatically after a short grace period.
- Monthly automated restore rehearsal in an isolated workshop.
- Quarterly full disaster-recovery exercise.

Business owners still need to approve platform-wide PITR targets. A reasonable
starting proposal is continuous WAL archiving with a 15-minute platform RPO and
a four-hour RTO; this does not replace nightly logical workshop recovery sets.

## Delivery phases

### Phase 1: Infrastructure and format

Create buckets, IAM, retention, encryption-key handling, the versioned manifest
schema, and S3 integration tests. A recovery point is not considered complete
until its commit marker is verified remotely.

### Phase 2: Full local recovery sets

Generalize the existing driver and database model. Make local snapshots include
Paperless conditionally and add strict module-scope validation. This establishes
the consistency and restore behavior before introducing remote storage.

### Phase 3: Encrypted S3 backups

Add the backup agent, bounded-memory encrypted multipart uploads, retry/resume
behavior, retention metadata, verification and operational metrics.

### Phase 4: Safe restore

Add prefix-scoped downloads, automatic safety backups, temporary restore targets,
health checks, rollback and cleanup. Keep legacy Odoo-only restore compatibility.

### Phase 5: Rehearsal and production enablement

Test both `documents` off and on, active invoice ingestion, corrupt/truncated
objects, wrong keys, expired credentials, worker crashes, scope mismatches and
rollback failures. Enable scheduling only after an isolated S3 restore preserves
Paperless document IDs, document checksums and Odoo links.

## Acceptance criteria

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
