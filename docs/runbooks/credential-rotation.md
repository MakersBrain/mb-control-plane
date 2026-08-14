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

After upgrading from the legacy shared Odoo bridge credential, reconcile every
routed workshop before admitting production traffic. Reconciliation upgrades
the bridge schema, writes a distinct random tenant token, authenticates the
versioned bootstrap receipt with the still-valid previous verifier, updates the
tenant-database hash, and updates the Paperless webhook file. Run
`make topology-odoo-isolation-check` against two workshops afterward. A workshop
that still accepts the other workshop's token remains in maintenance; never
delete or hand-edit its token file to force rotation.

For a planned privacy-export encryption-key rotation, place only the still-live
previous key IDs and base64 keys in the API's absolute, access-controlled JSON
key-ring file, set `CONTROL_PRIVACY_EXPORT_DECRYPTION_KEYS_FILE`, and deploy the
new current key ID/key atomically to the API and privacy worker. Remove each old
entry after its last export has been consumed or passed the seven-day maximum.
The key ring is decryption-only, bounded to 16 entries and 64 KiB; new exports
always use the current key. For suspected key compromise, do not retain the old
key: revoke access even though its outstanding exports become unavailable, and
record/reissue those requests through the privacy workflow.
