# Credential rotation

Rotate one scoped identity at a time. Compromise-triggered revocation takes
priority over the normal overlap sequence.

1. Resolve the process, database role, provider capability, owner, and approved
   secret-manager reference. Never paste the secret into a ticket or command
   transcript.
2. Issue a second credential with the same narrow grants and a bounded lifetime.
3. Deploy the new reference, drain the old connection/client pool, and verify
   heartbeats plus one non-destructive operation under the new identity.
4. Revoke the old credential and prove it can no longer authenticate.
5. Record issuer evidence, reference identifiers, timestamps, affected process,
   verifier, and emergency reason if applicable. Do not record secret values or
   password hashes.
6. If verification fails, restore the previous reference only while it remains
   valid; otherwise keep the owning queue stopped and follow the queue runbook.

Do not rotate by giving a worker a migration owner, another queue's credential,
or a shared provider administrator key.

Odoo bridge credentials are tenant-scoped from initial provisioning. The shared
process credential authenticates only the first bootstrap request for a blank
tenant database; it is not a tenant credential and is never a fallback after a
tenant verifier exists. Rotate a workshop token through the current
tenant-scoped provisioning/reconciliation contract, then run
`make topology-odoo-isolation-check` against two workshops. A workshop that
accepts the other workshop's token remains in maintenance; never delete or
hand-edit its token file to force rotation.

For a planned privacy-export encryption-key rotation, place only the still-live
previous key IDs and base64 keys in the API's absolute, access-controlled JSON
key-ring file, set `CONTROL_PRIVACY_EXPORT_DECRYPTION_KEYS_FILE`, and deploy the
new current key ID/key atomically to the API and privacy worker. Remove each old
entry after its last export has been consumed or passed the seven-day maximum.
The key ring is decryption-only, bounded to 16 entries and 64 KiB; new exports
always use the current key. For suspected key compromise, do not retain the old
key: revoke access even though its outstanding exports become unavailable, and
record/reissue those requests through the privacy workflow.

## Backup age recipient rotation

An age recipient is a write-time encryption selector, while its private
identity is recovery material. Rotate them as a pair without assuming that
changing the recipient makes retained backup sets readable by the new identity.

1. Generate the replacement identity in protected recovery custody and derive
   its public recipient without printing either value to logs or passing it as
   a command argument. Keep both files mode `0600` below a `0700` directory.
2. Store the new public recipient and a new non-secret key ID in the secret
   manager. Do not upload the private recovery identity to an application path.
3. Deploy the new recipient to backup writers. Keep the old private identity in
   recovery custody for every retained set encrypted to it; do not configure
   writers to keep using the old recipient merely to create an overlap.
4. Produce a new encrypted backup under the replacement recipient and restore
   it into an isolated target using only the replacement private identity.
5. Prove one still-retained old set remains restorable with the old identity,
   then record its expiry date. If no old set exists, record the inventory
   evidence rather than fabricating a restore.
6. After the final old set expires or is deliberately superseded by a verified
   replacement set, remove the old identity from host-accessible recovery
   bundles and revoke its secret-manager versions. Preserve any required
   offline legal/recovery escrow according to the retention policy.

For suspected disclosure, stop issuing new backups to the old recipient as
soon as the replacement restore passes. The old identity may remain in isolated
recovery custody only for the shortest retained-backup overlap; it must never
be installed in an ordinary application or backup-writer secret path. A restore
agent may receive the exact identity file read-only for the bounded recovery
operation; it must not receive either complete runtime secret root.
