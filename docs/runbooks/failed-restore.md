# Failed restore

1. Keep the workshop route in maintenance and confirm the safety recovery point
   reached verified storage before the selected restore began.
2. Distinguish corrupt/wrong-key input, download interruption, database restore,
   filestore checksum, Paperless linkage, and health verification failures.
3. If automatic rollback succeeded, verify the safety recovery manifest and
   application health before routing. If rollback is unresolved, do not clear
   maintenance manually.
4. Inspect `control.erasure_restore_replays`. The driver keeps the workshop in
   maintenance until every restored Odoo/Paperless location is complete. Never
   bypass `resume`; repair the missing key, lookup or processor adapter and
   retry the durable lifecycle operation.
5. Record the recovery point, component digests, encryption-key reference,
   result, operator identity, and follow-up action without copying personal data.

Restore credentials are unavailable to the backup scheduler and ordinary
workshop operators. Use the separately authorized restore path with recent
strong authentication.
