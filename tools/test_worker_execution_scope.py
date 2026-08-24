#!/usr/bin/env python3
"""Guard the fleet-lease/tenant-execution seam in durable workers."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


domain = (ROOT / "src/domain.rs").read_text()
persistence = (ROOT / "src/persistence.rs").read_text()
worker = (ROOT / "src/worker.rs").read_text()

routable_domains = worker.split(
    "pub(crate) async fn routable_custom_hostnames(", 1
)[1].split("\npub async fn run", 1)[0]
require(
    "tx: &mut WorkshopTransaction<'_>" in routable_domains
    and "tx.workshop_id()" in routable_domains
    and "store.pool()" not in routable_domains,
    "routable custom hostnames must require a workshop transaction",
)
enable_paperless = worker.split("async fn enable_paperless(", 1)[1].split(
    "\nasync fn ", 1
)[0]
require(
    re.search(r"tenant_store\s*\.begin_repeatable_read\(workshop\)", enable_paperless)
    is not None
    and "routable_custom_hostnames(&mut snapshot_tx)" in enable_paperless
    and enable_paperless.find("snapshot_tx\n        .commit()")
    < enable_paperless.find("let value = driver_request("),
    "Paperless route input must be read in a short workshop snapshot before driver I/O",
)

require(
    "pub enum OperationExecutionScope" in domain
    and "Workshop(Uuid)" in domain
    and "Fleet" in domain,
    "operation execution scope must be a closed tenant/fleet enum",
)
for global_kind in [
    "Self::OdooReleaseAdopt",
    "Self::PrivacyRetention",
    "Self::PrivacyDataSubjectRequest",
]:
    require(global_kind in domain, f"missing explicit global kind {global_kind}")
require(
    "leased_queue != self.queue()" in domain,
    "leased operations must reject queue/kind mismatches",
)
require(
    "worker_tenant_scope" in persistence and "pool: self.pool.clone()" in persistence,
    "worker tenant capability must reuse the queue-specific worker pool",
)

lease = worker.find("store.lease(queue,&worker_id)")
validate = worker.find("validate_operation(queue, &operation)")
handle = worker.find("handle(&store, &tenant_store, operation, &config)")
finish = worker.find("store.finish(&operation,outcome)")
require(
    -1 not in (lease, validate, handle, finish) and lease < validate < handle < finish,
    "workers must validate scope after fleet lease and before dispatch/finalization",
)
require(
    worker.count("contract_valid && operation.kind") >= 6,
    "invalid operation contracts must not invoke tenant failure callbacks",
)
require(
    "async fn guard_operation_lease" in worker
    and "GuardedOperation::LeaseLost" in worker
    and "operation_work.instrument(span)" in worker
    and "tokio::spawn" not in worker,
    "operation handlers and terminal callbacks must remain inside structured lease cancellation",
)
require(
    "terminal_cleanup_error" in worker
    and "IntegrationError::UnknownOutcome" in worker
    and "mark_module_activation_failed(" in worker,
    "a failed terminal cleanup must remain durably reconcilable rather than dead-lettering",
)
require(
    persistence.count("and lease_expires_at>now()") >= 3
    and "and leased_by=$2 and attempt=$3 and state='in_flight'\n               and lease_expires_at>now()" in persistence
    and "and lease_expires_at>now() and checkpoint is null" in persistence,
    "expired durable-operation authority must not renew, checkpoint, or finalize",
)

membership = worker.split("async fn membership(", 1)[1].split(
    "fn paperless_group_names", 1
)[0]
require(
    "tenant_store: &TenantStore" in membership,
    "membership execution must receive only the tenant database capability",
)
require(
    re.search(r"tenant_store\s*\.begin\(workshop\)", membership) is not None,
    "membership snapshots must install transaction-local workshop context",
)
require(
    "store.pool()" not in membership and "service(store" not in membership,
    "membership execution must not reach the fleet store",
)
require(
    membership.find("tx.commit()") < membership.find("RauthyClient::new"),
    "membership must release its snapshot transaction before outbound I/O",
)

record_target = worker.split("async fn record_target(", 1)[1].split(
    "async fn entitlement(", 1
)[0]
require(
    re.search(r"tenant_store\s*\.begin\(workshop\)", record_target) is not None
    and "tx.commit()" in record_target,
    "membership result writes must use short workshop transactions",
)

entitlement = worker.split("async fn entitlement(", 1)[1].split(
    "pub(crate) async fn driver", 1
)[0]
require(
    re.search(r"tenant_store\s*\.begin\(workshop\)", entitlement) is not None
    and entitlement.find("tx.commit()") < entitlement.find("OdooClient::new"),
    "entitlement snapshots must commit before outbound Odoo I/O",
)

email = (ROOT / "src/workers/email.rs").read_text()
deliver = email.split("pub(crate) async fn deliver(", 1)[1].split("#[cfg(test)]", 1)[0]
require(
    "tenant_store: &TenantStore" in deliver and "workshop: Uuid" in deliver,
    "email delivery must receive the validated tenant capability and workshop",
)
require(
    deliver.find("owned_outbox(tenant_store, workshop, outbox).await?")
    < deliver.find("load_invitation_signer()")
    < deliver.find(".send()"),
    "outbox ownership must be resolved before signing or provider I/O",
)
require(
    "store.pool()" not in deliver,
    "email delivery must not reach the fleet database capability",
)

lifecycle = (ROOT / "src/workers/lifecycle.rs").read_text()
onboarding = (ROOT / "src/workers/onboarding.rs").read_text()
email_domains = (ROOT / "src/workers/email_domains.rs").read_text()
for name, source in [
    ("lifecycle", lifecycle),
    ("onboarding", onboarding),
    ("email domains", email_domains),
]:
    require(
        "lock_current_operation_lease" in source,
        f"{name} terminal cleanup must lock the exact live operation lease",
    )
production_lifecycle = lifecycle.split("#[cfg(test)]", 1)[0]
run = production_lifecycle.split("pub(crate) async fn run(", 1)[1].split(
    "async fn prepare(", 1
)[0]
prepare = production_lifecycle.split("async fn prepare(", 1)[1].split(
    "async fn finalize(", 1
)[0]
delete_lock = run.find("let source_locked = sqlx::query_scalar")
delete_route_apply = run.find("super::routes::apply(")
maintenance_validation = run.find(
    "validate_resource_ownership(&mut validation, operation, command).await?"
)
maintenance_driver = run.find("let response = driver_request_with_key(")
prepare_call = run.find("prepare(tenant_store, workshop, operation, command).await?")
lifecycle_driver = run.find("let value = driver_request_with_key(")
finalize_call = run.find("finalize(")
require(
    -1 not in (delete_lock, delete_route_apply)
    and delete_lock < delete_route_apply,
    "delete route tombstones must validate their owned lifecycle resources before driver I/O",
)
require(
    -1 not in (maintenance_validation, maintenance_driver)
    and maintenance_validation < maintenance_driver,
    "restore maintenance must validate resource ownership before driver I/O",
)
require(
    -1 not in (prepare_call, lifecycle_driver, finalize_call)
    and prepare_call < lifecycle_driver < finalize_call,
    "lifecycle preparation must complete before the lifecycle effect and finalization",
)
require(
    prepare.find("validate_resource_ownership(&mut tx, operation, command).await?")
    < prepare.find("progress_percent=2")
    < prepare.find("tx.commit()"),
    "lifecycle ownership must be resolved before progress, mutation, or driver I/O",
)
require(
    re.search(r"\bStore\b", production_lifecycle) is None
    and "store.pool()" not in production_lifecycle
    and "store.begin()" not in production_lifecycle,
    "lifecycle tenant execution and compensation must not receive the fleet store",
)
require(
    "lifecycle::run(\n                    tenant_store," in worker
    and "terminal_cleanup_error = crate::workers::lifecycle::failed(" in worker,
    "lifecycle dispatch and terminal cleanup must receive only the tenant capability",
)
failed = production_lifecycle.split("pub(crate) async fn failed(", 1)[1]
require(
    "tenant_store: &TenantStore" in failed
    and "tenant_store.begin(workshop)" in failed
    and "where workshop_id=$1 and operation_id=$2" in failed,
    "lifecycle failure cleanup must retain workshop and operation ownership",
)

print("worker fleet leasing and tenant execution ownership boundaries are separated")
