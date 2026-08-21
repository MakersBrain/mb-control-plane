# Control-plane schema epoch reset

Use this runbook only for a disposable local or non-production environment. It
destroys every database, container, volume, tenant secret, identity client,
gateway route, Redis ACL user, recovery object, and privacy artifact created by
the old control-plane epoch. It does not preserve or migrate data.

## Preconditions

1. Record the environment name, code revision, release digests, and operator.
2. Prove from the deployment inventory that the target is not production.
3. Confirm that no data or recovery artifact in the target must be retained.
4. Stop external automation that could recreate or mutate the topology.

Do not use workshop deletion as a substitute. That workflow intentionally
creates a final recovery set and retains a quarantined tenant for 30 days.

## Stop and destroy

1. Stop ingress, the API, queue workers, schedulers, migration job, and
   provisioning/deployment driver.
2. Use the environment owner's destructive reset procedure to remove the full
   topology. For the repository-owned local Compose topology, remove the
   Compose project and its named volumes, then remove the ignored generated
   configuration and secret directories using explicit paths.
3. Remove provider-side development resources that are not owned by Compose:
   tenant Rauthy clients, gateway routes, Redis ACL users, object-store recovery
   prefixes, and privacy-export objects.
4. Query each provider independently and record that no resource from the old
   epoch remains. Do not start the new control plane if the absence check is
   incomplete.

## Recreate the base topology

1. Check out an immutable build containing the new base migration and matching
   release contract.
2. Run `./deploy/bootstrap-local-env.sh` to create a new file-backed secret
   layout. Never reuse an old secret directory or plaintext environment file.
3. Create the PostgreSQL service and runtime roles, then run the one-shot
   control migration. Confirm that the only SQLx row names
   `0001_control_plane_base` and that only capability registry version 1 is
   active.
4. Start the remaining control-plane services and confirm their readiness and
   worker heartbeats.

## Activate the first application release

1. Publish the signed application-release manifest through the normal release
   API. Its capability registry must be version 1 and its schema epoch must
   match the new release contract.
2. Run normal preflight and verify the prepared runtime slot, provenance,
   signature, image digest, bridge contract, and required postconditions.
3. Invoke initial empty-fleet activation. Confirm that the release and prepared
   runtime slot become active and that an immutable audit event is present.
4. Attempting empty-fleet activation again must fail. Never seed or manually
   update application-release rows.

## Qualify the fresh environment

1. Provision two synthetic workshops through the public workflow.
2. Confirm that each tenant adoption records the registry declared by the
   active application release.
3. Run the cross-tenant token, hostname, database, Paperless, secret-subpath,
   and Redis isolation gates.
4. Create and restore a recovery set in the current complete workshop format.
5. Restart the complete topology. Confirm readiness, worker heartbeats, routes,
   tenant isolation, and release state after reboot.
6. Retain reset logs and qualification evidence. They are diagnostic evidence,
   not a backup or migration source.

## Failure handling

There is no data rollback. Stop the failed topology, preserve only diagnostic
evidence, and destroy it. Recreate a blank topology after fixing the fault, or
create a blank topology from the previous code and its complete original
migration chain. Never combine a database from one epoch with code from the
other, and never modify the SQLx ledger.
