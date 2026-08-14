# Queue and worker failure

Use the platform status page first. It exposes worker freshness, due age,
dead-letter count, active operation and safe failure classes without exposing
payloads or personal data.

1. Confirm whether one queue or every queue is stale. A platform-wide failure
   points to PostgreSQL, deployment, or credential rotation; one queue points
   to its narrowly scoped worker.
2. Preserve the operation ID and correlation ID. Do not copy payloads, tenant
   secrets, emails, tokens, or provider responses into an incident ticket.
3. Restore the worker with its documented database role and secret set. Do not
   substitute another worker's credential.
4. Let an expired lease become reclaimable. For an unknown external outcome,
   reconcile provider state before retrying.
5. Use the safe retry action only for a dead letter whose failure class is
   understood. Escalate privacy operations to a privacy reviewer and release
   operations to a release operator.
6. Close the incident only after queue age returns to zero or a documented
   maintenance state remains visible.

Never edit an operation, command, audit row, or worker heartbeat manually.
