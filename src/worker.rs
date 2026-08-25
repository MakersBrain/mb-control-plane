use std::future::Future;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tracing::Instrument as _;
use uuid::Uuid;

use crate::domain::{IntegrationError, OperationExecutionScope, OperationKind};
use crate::integrations::extraction::ExtractionBrokerClient;
use crate::integrations::odoo::{
    EntitlementCommand, MembershipCommand, ModuleEnableCommand, ModuleRestrictCommand, OdooClient,
};
use crate::integrations::paperless::PaperlessClient;
use crate::integrations::rauthy::RauthyClient;
use crate::outbound_http::TraceRequestBuilderExt as _;
use crate::persistence::{
    LeasedOperation, OperationOutcome, Store, TenantStore, WorkshopTransaction,
    lock_current_operation_lease,
};
use crate::privacy_crypto;
use crate::worker_config::{DeploymentDriverConfig, WorkerConfig};

const QUEUES: [&str; 9] = [
    "tenant-provisioning",
    "membership-provisioning",
    "invoice-capture",
    "inventory-capture",
    "email-delivery",
    "tenant-reconciliation",
    "tenant-lifecycle",
    "release-adoption",
    "privacy-operations",
];
const TENANT_RECONCILIATION_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
const WEBSHOP_DOMAIN_RECONCILIATION_INTERVAL: Duration = Duration::from_secs(5 * 60);
const WEBSHOP_EMAIL_DOMAIN_RECONCILIATION_INTERVAL: Duration = Duration::from_secs(5 * 60);
const PERIODIC_ADMISSION_PAGE_SIZE: i32 = 500;
const MAX_ADMISSION_PAGES_PER_TICK: usize = 8;
const OPERATION_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(20);
const OPERATION_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, PartialEq, Eq)]
enum GuardedOperation<T> {
    Completed(T),
    LeaseLost,
}

/// Run one durable handler under structured lease ownership.
///
/// No heartbeat task outlives `work`: completion drops the timer, while a
/// definitive renewal failure drops (and therefore cancels) `work` before the
/// caller can run terminal compensation or finalization.
async fn guard_operation_lease<T, E, Work, Renew, RenewFuture>(
    work: Work,
    heartbeat_interval: Duration,
    mut renew: Renew,
) -> Result<GuardedOperation<T>, E>
where
    Work: Future<Output = T>,
    Renew: FnMut() -> RenewFuture,
    RenewFuture: Future<Output = Result<bool, E>>,
{
    tokio::pin!(work);
    loop {
        tokio::select! {
            biased;
            result = &mut work => return Ok(GuardedOperation::Completed(result)),
            _ = tokio::time::sleep(heartbeat_interval) => {
                if !renew().await? {
                    return Ok(GuardedOperation::LeaseLost);
                }
            }
        }
    }
}

enum ValidatedOperation<'a> {
    Workshop {
        kind: OperationKind,
        workshop_id: Uuid,
        operation: &'a LeasedOperation,
    },
    Fleet {
        kind: OperationKind,
        operation: &'a LeasedOperation,
    },
}

fn validate_operation<'a>(
    queue: &str,
    operation: &'a LeasedOperation,
) -> Result<ValidatedOperation<'a>, IntegrationError> {
    let kind = operation
        .kind
        .parse::<OperationKind>()
        .map_err(|_| IntegrationError::ContractDrift)?;
    match kind
        .execution_scope(queue, operation.workshop_id)
        .map_err(|_| IntegrationError::ContractDrift)?
    {
        OperationExecutionScope::Workshop(workshop_id) => Ok(ValidatedOperation::Workshop {
            kind,
            workshop_id,
            operation,
        }),
        OperationExecutionScope::Fleet => Ok(ValidatedOperation::Fleet { kind, operation }),
    }
}

pub(crate) async fn routable_custom_hostnames(
    tx: &mut WorkshopTransaction<'_>,
) -> Result<Value, sqlx::Error> {
    let workshop = tx.workshop_id();
    sqlx::query_scalar::<_, Value>(
        "select coalesce(jsonb_agg(jsonb_build_object(
                    'hostname',hostname,'canonical',canonical) order by hostname),'[]'::jsonb)
           from control.webshop_domains
          where workshop_id=$1 and state in ('testing','active') and desired_state='active'",
    )
    .bind(workshop)
    .fetch_one(&mut **tx)
    .await
}

pub async fn run(store: Store, queue: &str, config: WorkerConfig) -> anyhow::Result<()> {
    if !QUEUES.contains(&queue) {
        anyhow::bail!("unknown worker queue {queue}")
    }
    if queue == "release-adoption" {
        crate::workers::release::validate_configuration()?;
    }
    if matches!(queue, "tenant-lifecycle" | "privacy-operations") {
        privacy_crypto::validate_configuration()
            .map_err(|_| anyhow::anyhow!("privacy lookup encryption is not configured"))?;
    }
    if queue == "privacy-operations" {
        privacy_crypto::validate_export_configuration()
            .map_err(|_| anyhow::anyhow!("privacy export encryption is not configured"))?;
    }
    let worker_id = format!("{queue}-{}", Uuid::new_v4());
    let tenant_store = store.worker_tenant_scope();
    store
        .start_worker(&worker_id, queue, config.release_id())
        .await?;
    tracing::info!(queue,worker=%worker_id,"worker started");
    let mut next_privacy_export_cleanup = Instant::now();
    let mut next_tenant_reconciliation = Instant::now();
    let mut next_webshop_domain_reconciliation = Instant::now();
    let mut next_webshop_email_domain_reconciliation = Instant::now();
    loop {
        tokio::select! {
            _=tokio::time::sleep(Duration::from_secs(2))=>{
                if !store.heartbeat_worker(&worker_id,None).await? {
                    anyhow::bail!("worker heartbeat registration disappeared")
                }
                if queue == "tenant-reconciliation" {
                    admit_capability_restriction(&store).await?;
                    if Instant::now() >= next_webshop_domain_reconciliation {
                        let admitted = admit_webshop_domain_reconciliation(&store).await?;
                        tracing::info!(admitted,"admitted webshop domain reconciliation operations");
                        next_webshop_domain_reconciliation = Instant::now() + WEBSHOP_DOMAIN_RECONCILIATION_INTERVAL;
                    }
                    if Instant::now() >= next_webshop_email_domain_reconciliation {
                        let admitted = admit_webshop_email_domain_reconciliation(&store).await?;
                        tracing::info!(admitted,"admitted webshop email domain reconciliation operations");
                        next_webshop_email_domain_reconciliation = Instant::now() + WEBSHOP_EMAIL_DOMAIN_RECONCILIATION_INTERVAL;
                    }
                    if Instant::now() >= next_tenant_reconciliation {
                        let admitted = admit_periodic_tenant_reconciliation(
                            &store,
                            tenant_domain(&config)?,
                        ).await?;
                        tracing::info!(admitted,"admitted periodic tenant reconciliation operations");
                        next_tenant_reconciliation = Instant::now() + TENANT_RECONCILIATION_INTERVAL;
                    }
                }
                if queue == "privacy-operations" && Instant::now() >= next_privacy_export_cleanup {
                    let deleted = crate::workers::privacy::cleanup_export_artifacts(&store, &worker_id)
                        .await
                        .map_err(|_| anyhow::anyhow!("privacy export artifact cleanup failed"))?;
                    if deleted > 0 {
                        tracing::info!(deleted,"purged expired or consumed privacy export artifacts");
                    }
                    next_privacy_export_cleanup = Instant::now() + Duration::from_secs(60);
                }
                if let Some(operation)=store.lease(queue,&worker_id).await?{
                    if !store.heartbeat_worker(&worker_id,Some(operation.id)).await? {
                        anyhow::bail!("worker heartbeat registration disappeared")
                    }
                    let span = tracing::info_span!(
                        "durable_operation",
                        operation_id = %operation.id,
                        operation_kind = operation_kind_class(&operation.kind),
                        attempt = operation.attempt,
                        reconciling = operation.reconciling
                    );
                    if crate::telemetry::attach_durable_trace_parent(
                        &span,
                        operation.trace_parent.as_deref(),
                        operation.trace_state.as_deref(),
                    )
                    .is_err()
                    {
                        tracing::warn!(
                            error_class = "trace_parent_rejected",
                            "durable operation trace context was not attached"
                        );
                    }
                    let validated = validate_operation(queue, &operation);
                    let contract_valid = validated.is_ok();
                    let operation_work = async {
                        let mut result = match &validated {
                            Ok(operation) => handle(&store, &tenant_store, operation, &config).await,
                            Err(error) => Err(*error),
                        };
                        let mut terminal_cleanup_error = None;
                        if contract_valid && operation.kind == "tenant.lifecycle"
                                && result.as_ref().is_err_and(|error| !error.retryable() || operation.attempt >= operation.max_attempts)
                                && let Some(workshop) = operation.workshop_id
                        {
                            terminal_cleanup_error = crate::workers::lifecycle::failed(
                                &tenant_store,
                                workshop,
                                &operation,
                            )
                            .await
                            .err();
                        }
                        if contract_valid && operation.kind == "odoo.release.adopt"
                                && result.as_ref().is_err_and(|error| {
                                    release_failure_is_terminal(
                                        *error,
                                        operation.attempt,
                                        operation.max_attempts,
                                    )
                                })
                        {
                            terminal_cleanup_error = crate::workers::release::failed(
                                &store,
                                &operation,
                            )
                            .await
                            .err();
                        }
                        if contract_valid && operation.kind == "webshop-onboarding.reconcile"
                                && result.as_ref().is_err_and(|error| !error.retryable() || operation.attempt >= operation.max_attempts)
                        {
                            terminal_cleanup_error = crate::workers::onboarding::failed(
                                &store,
                                &operation,
                            )
                            .await
                            .err();
                        }
                        if contract_valid && operation.kind == "webshop-domain.reconcile"
                                && result.as_ref().is_err_and(|error| {
                                    domain_failure_is_terminal(
                                        *error,
                                        operation.attempt,
                                        operation.max_attempts,
                                    )
                                })
                                && let Some(workshop) = operation.workshop_id
                        {
                            terminal_cleanup_error = crate::workers::domains::failed(
                                &tenant_store,
                                workshop,
                                &operation,
                            )
                            .await
                            .err();
                        }
                        if contract_valid && operation.kind == "webshop-email-domain.reconcile"
                                && result.as_ref().is_err_and(|error| !error.retryable() || operation.attempt >= operation.max_attempts)
                        {
                            terminal_cleanup_error = crate::workers::email_domains::failed(
                                &tenant_store,
                                &operation,
                            )
                            .await
                            .err();
                        }
                        if contract_valid && operation.kind == "module.enable"
                                && result.as_ref().is_err_and(|error| !error.retryable() || operation.attempt >= operation.max_attempts)
                                && let (Some(workshop),Some(module_key))=(operation.workshop_id,operation.payload.get("module_key").and_then(Value::as_str))
                                && let Err(error)=mark_module_activation_failed(
                                    &store,
                                    &operation,
                                    workshop,
                                    module_key,
                                ).await
                        {
                            tracing::error!(
                                operation=%operation.id,
                                error_class=crate::error_reporting::safe_error_class(&error),
                                "could not mark capability activation failed"
                            );
                            terminal_cleanup_error = Some(error);
                        }
                        if let Some(error) = terminal_cleanup_error {
                            result = Err(if matches!(error, IntegrationError::ContractDrift) {
                                IntegrationError::ContractDrift
                            } else {
                                IntegrationError::UnknownOutcome
                            });
                        }
                        result
                    };
                    let heartbeat_store = store.clone();
                    let heartbeat_operation_id = operation.id;
                    let heartbeat_worker = operation.leased_by.clone();
                    let heartbeat_attempt = operation.attempt;
                    let guarded = guard_operation_lease(
                        operation_work.instrument(span),
                        OPERATION_HEARTBEAT_INTERVAL,
                        move || {
                            let heartbeat_store = heartbeat_store.clone();
                            let heartbeat_worker = heartbeat_worker.clone();
                            async move {
                                tokio::time::timeout(OPERATION_HEARTBEAT_TIMEOUT, async {
                                    if !heartbeat_store
                                        .renew_lease(
                                            heartbeat_operation_id,
                                            &heartbeat_worker,
                                            heartbeat_attempt,
                                        )
                                        .await?
                                    {
                                        return Ok(false);
                                    }
                                    Ok::<bool, anyhow::Error>(
                                        heartbeat_store
                                            .heartbeat_worker(
                                                &heartbeat_worker,
                                                Some(heartbeat_operation_id),
                                            )
                                            .await?,
                                    )
                                })
                                .await
                                .map_err(|_| anyhow::anyhow!("operation lease heartbeat timed out"))?
                            }
                        },
                    )
                    .await;
                    let result = match guarded {
                        Ok(GuardedOperation::Completed(result)) => result,
                        Ok(GuardedOperation::LeaseLost) => {
                            tracing::warn!(
                                operation = %operation.id,
                                operation_kind = operation_kind_class(&operation.kind),
                                attempt = operation.attempt,
                                outcome = "lease_lost",
                                "durable operation cancelled after lease loss"
                            );
                            if !store.heartbeat_worker(&worker_id, None).await? {
                                anyhow::bail!("worker heartbeat registration disappeared")
                            }
                            continue;
                        }
                        Err(error) => {
                            let (error_classes, error_chain_truncated) =
                                crate::error_reporting::safe_anyhow_chain(&error);
                            tracing::warn!(
                                operation = %operation.id,
                                operation_kind = operation_kind_class(&operation.kind),
                                attempt = operation.attempt,
                                ?error_classes,
                                error_chain_truncated,
                                outcome = "heartbeat_unavailable",
                                "durable operation cancelled after heartbeat failure"
                            );
                            let _ = store.shutdown_worker(&worker_id).await;
                            return Err(anyhow::anyhow!("operation lease heartbeat failed"));
                        }
                    };
                    log_operation_result(&operation, &result);
                    let outcome=match result{
                        Ok(())=>OperationOutcome::Succeeded,
                        Err(IntegrationError::UnknownOutcome)=>OperationOutcome::Unknown,
                        Err(error) if error.retryable()=>OperationOutcome::Retry(error),
                        Err(error)=>OperationOutcome::Failed(error),
                    };
                    store.finish(&operation,outcome).await?;
                    store.heartbeat_worker(&worker_id,None).await?;
                }
            }
            _=crate::shutdown_signal()=>{
                store.shutdown_worker(&worker_id).await?;
                break
            },
        }
    }
    Ok(())
}

async fn admit_webshop_email_domain_reconciliation(store: &Store) -> anyhow::Result<usize> {
    let trace = crate::telemetry::current_trace_context();
    let mut admitted = 0;
    // A zero-row page can consist entirely of same-window idempotency
    // conflicts. Always advance a fixed number of durable-cursor pages rather
    // than treating an empty result as end-of-scan.
    for _ in 0..MAX_ADMISSION_PAGES_PER_TICK {
        let rows = sqlx::query_as::<_, (Uuid, Uuid, Uuid)>(
            "select operation_id,workshop_id,email_domain_id
               from control.admit_due_webshop_email_domain_reconciliations($1,$2,$3)",
        )
        .bind(PERIODIC_ADMISSION_PAGE_SIZE)
        .bind(trace.trace_parent.clone())
        .bind(trace.trace_state.clone())
        .fetch_all(store.pool())
        .await?;
        admitted += rows.len();
    }
    Ok(admitted)
}

async fn admit_webshop_domain_reconciliation(store: &Store) -> anyhow::Result<usize> {
    let trace = crate::telemetry::current_trace_context();
    let mut admitted = 0;
    for _ in 0..MAX_ADMISSION_PAGES_PER_TICK {
        let rows = sqlx::query_as::<_, (Uuid, Uuid, Uuid)>(
            "select operation_id,workshop_id,domain_id
             from control.admit_due_webshop_domain_reconciliations($1,$2,$3)",
        )
        .bind(PERIODIC_ADMISSION_PAGE_SIZE)
        .bind(trace.trace_parent.clone())
        .bind(trace.trace_state.clone())
        .fetch_all(store.pool())
        .await?;
        admitted += rows.len();
    }
    Ok(admitted)
}

async fn admit_periodic_tenant_reconciliation(
    store: &Store,
    domain: &str,
) -> anyhow::Result<usize> {
    let trace = crate::telemetry::current_trace_context();
    let mut admitted = 0;
    for _ in 0..MAX_ADMISSION_PAGES_PER_TICK {
        let rows = sqlx::query_as::<_, (Uuid, Uuid)>(
            "select operation_id,workshop_id
               from control.admit_due_tenant_reconciliations($1,$2,$3,$4)",
        )
        .bind(PERIODIC_ADMISSION_PAGE_SIZE)
        .bind(domain)
        .bind(trace.trace_parent.clone())
        .bind(trace.trace_state.clone())
        .fetch_all(store.pool())
        .await?;
        admitted += rows.len();
    }
    Ok(admitted)
}

async fn handle(
    store: &Store,
    tenant_store: &TenantStore,
    validated: &ValidatedOperation<'_>,
    config: &WorkerConfig,
) -> Result<(), IntegrationError> {
    let operation = match validated {
        ValidatedOperation::Workshop { operation, .. }
        | ValidatedOperation::Fleet { operation, .. } => *operation,
    };
    tracing::info!(
        operation=%operation.id,
        operation_kind=operation_kind_class(&operation.kind),
        attempt=operation.attempt,
        reconciling=operation.reconciling,
        "handling operation"
    );
    match validated {
        ValidatedOperation::Workshop {
            kind,
            workshop_id,
            operation,
        } => match kind {
            OperationKind::MembershipReconcile => {
                membership(tenant_store, *workshop_id, operation).await
            }
            OperationKind::EntitlementApply => {
                entitlement(tenant_store, *workshop_id, operation).await
            }
            OperationKind::InvoiceCapture => {
                crate::workers::extraction::invoice(
                    store,
                    operation,
                    tenant_domain(config)?,
                    config
                        .invoice_extraction()
                        .ok_or(IntegrationError::ContractDrift)?,
                )
                .await
            }
            OperationKind::InventoryCaptureExtract => {
                crate::workers::extraction::inventory_capture(
                    store,
                    operation,
                    config
                        .inventory_extraction()
                        .ok_or(IntegrationError::ContractDrift)?,
                )
                .await
            }
            OperationKind::TenantProvision => driver(
                tenant_store,
                operation,
                "provision",
                tenant_domain(config)?,
                deployment_driver(config)?,
            )
            .await
            .map(|_| ()),
            OperationKind::TenantReconcile => driver(
                tenant_store,
                operation,
                "reconcile",
                tenant_domain(config)?,
                deployment_driver(config)?,
            )
            .await
            .map(|_| ()),
            OperationKind::TenantLifecycle => {
                crate::workers::lifecycle::run(
                    tenant_store,
                    *workshop_id,
                    operation,
                    deployment_driver(config)?,
                )
                .await
            }
            OperationKind::EmailDelivery => {
                crate::workers::email::deliver(
                    tenant_store,
                    *workshop_id,
                    operation,
                    config
                        .email_delivery()
                        .ok_or(IntegrationError::ContractDrift)?,
                )
                .await
            }
            OperationKind::ModuleEnable => {
                enable_module(
                    store,
                    tenant_store,
                    operation,
                    tenant_domain(config)?,
                    deployment_driver(config)?,
                )
                .await
            }
            OperationKind::ModuleRestrict => {
                restrict_module(
                    store,
                    tenant_store,
                    operation,
                    tenant_domain(config)?,
                    deployment_driver(config)?,
                )
                .await
            }
            OperationKind::WebshopDomainReconcile => {
                crate::workers::domains::run(
                    tenant_store,
                    *workshop_id,
                    operation,
                    tenant_domain(config)?,
                    deployment_driver(config)?,
                    config
                        .custom_hostname_provider()
                        .ok_or(IntegrationError::ContractDrift)?,
                )
                .await
            }
            OperationKind::WebshopEmailDomainReconcile => {
                crate::workers::email_domains::run(store, tenant_store, operation).await
            }
            OperationKind::WebshopOnboardingReconcile => {
                crate::workers::onboarding::run(store, operation).await
            }
            OperationKind::OdooReleaseAdopt
            | OperationKind::PrivacyRetention
            | OperationKind::PrivacyDataSubjectRequest => Err(IntegrationError::ContractDrift),
        },
        ValidatedOperation::Fleet { kind, operation } => match kind {
            OperationKind::OdooReleaseAdopt => {
                crate::workers::release::adopt(store, operation, deployment_driver(config)?).await
            }
            OperationKind::PrivacyRetention => {
                crate::workers::privacy::retention(store, operation).await
            }
            OperationKind::PrivacyDataSubjectRequest => {
                crate::workers::privacy::data_subject_request(
                    store,
                    tenant_store,
                    operation,
                    config
                        .privacy_driver()
                        .ok_or(IntegrationError::ContractDrift)?,
                )
                .await
            }
            OperationKind::TenantProvision
            | OperationKind::MembershipReconcile
            | OperationKind::EntitlementApply
            | OperationKind::InvoiceCapture
            | OperationKind::InventoryCaptureExtract
            | OperationKind::TenantReconcile
            | OperationKind::TenantLifecycle
            | OperationKind::EmailDelivery
            | OperationKind::ModuleEnable
            | OperationKind::ModuleRestrict
            | OperationKind::WebshopDomainReconcile
            | OperationKind::WebshopEmailDomainReconcile
            | OperationKind::WebshopOnboardingReconcile => Err(IntegrationError::ContractDrift),
        },
    }
}

async fn enable_module(
    store: &Store,
    tenant_store: &TenantStore,
    operation: &LeasedOperation,
    tenant_domain: &str,
    deployment_driver: &DeploymentDriverConfig,
) -> Result<(), IntegrationError> {
    let workshop = operation
        .workshop_id
        .ok_or(IntegrationError::ContractDrift)?;
    let module_key = operation
        .payload
        .get("module_key")
        .and_then(Value::as_str)
        .ok_or(IntegrationError::ContractDrift)?;
    let bundle = crate::modules::bundle(module_key).ok_or(IntegrationError::ContractDrift)?;
    let registry_version = operation
        .payload
        .get("registry_version")
        .and_then(Value::as_i64)
        .and_then(|value| i32::try_from(value).ok())
        .ok_or(IntegrationError::ContractDrift)?;
    let release_id = operation
        .payload
        .get("application_release_id")
        .and_then(Value::as_str)
        .ok_or(IntegrationError::ContractDrift)?;
    let entitlement_version = operation
        .payload
        .get("entitlement_version")
        .and_then(Value::as_i64)
        .ok_or(IntegrationError::ContractDrift)?;
    let resolved = operation
        .payload
        .get("resolved_implementation")
        .ok_or(IntegrationError::ContractDrift)?;
    let resolved_modules = resolved
        .get("odoo_modules")
        .and_then(Value::as_array)
        .ok_or(IntegrationError::ContractDrift)?;
    if resolved_modules.len() != bundle.odoo_modules.len()
        || resolved_modules
            .iter()
            .zip(bundle.odoo_modules)
            .any(|(actual, expected)| actual.as_str() != Some(expected))
        || resolved.get("service").and_then(Value::as_str) != bundle.service
    {
        return Err(IntegrationError::ContractDrift);
    }
    let pinned = sqlx::query_as::<
        _,
        (
            i32,
            Option<String>,
            Option<i64>,
            Value,
            String,
            Option<Uuid>,
        ),
    >(
        "select registry_version,application_release_id,entitlement_version,
                resolved_implementation,state,operation_id
         from control.workshop_modules where workshop_id=$1 and module_key=$2",
    )
    .bind(workshop)
    .bind(module_key)
    .fetch_optional(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .ok_or(IntegrationError::NotFound)?;
    if pinned.0 != registry_version
        || pinned.1.as_deref() != Some(release_id)
        || pinned.2 != Some(entitlement_version)
        || pinned.3 != *resolved
        || pinned.5 != Some(operation.id)
    {
        return Err(IntegrationError::ContractDrift);
    }
    if pinned.4 == "enabled" {
        return Ok(());
    }
    let entitled = sqlx::query_scalar::<_, bool>(
        "select exists(
           select 1 from control.entitlements e
           join control.tenant_release_adoptions a on a.workshop_id=e.workshop_id
           where e.workshop_id=$1 and e.version=$3 and e.status='active'
             and (e.expires_at is null or e.expires_at>now())
             and (coalesce(e.limits->'capabilities','[]'::jsonb) ? $2
                  or coalesce(e.limits->'capabilities','[]'::jsonb) ? '*')
             and a.release_id=$4 and a.registry_version=$5 and a.state='active'
         )",
    )
    .bind(workshop)
    .bind(module_key)
    .bind(entitlement_version)
    .bind(release_id)
    .bind(registry_version)
    .fetch_one(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    if !entitled {
        return Err(IntegrationError::Rejected);
    }
    if pinned.4 == "requested" {
        sqlx::query(
            "update control.workshop_modules set state='installing',version=version+1
             where workshop_id=$1 and module_key=$2 and operation_id=$3 and state='requested'",
        )
        .bind(workshop)
        .bind(module_key)
        .bind(operation.id)
        .execute(store.pool())
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    } else if pinned.4 != "installing" {
        return Err(IntegrationError::ContractDrift);
    }
    if bundle.service == Some("paperless") {
        enable_paperless(
            tenant_store,
            operation,
            workshop,
            tenant_domain,
            deployment_driver,
        )
        .await?;
    } else if matches!(
        module_key,
        "azure-invoice-extraction" | "azure-label-extraction"
    ) {
        extraction_broker(Duration::from_secs(5))?.ready().await?;
    } else if module_key == "inventory-ai-fallback" {
        extraction_broker(Duration::from_secs(5))?
            .vision_ready()
            .await?;
    } else if !bundle.odoo_modules.is_empty() {
        let (odoo_url, odoo_ref, database_ref) = service(store, workshop, "odoo").await?;
        let odoo = OdooClient::new(
            &odoo_url,
            &secret(&odoo_ref)?,
            database_ref.as_deref(),
            Duration::from_secs(120),
        )
        .map_err(|_| IntegrationError::ContractDrift)?;
        odoo.enable_modules(&ModuleEnableCommand {
            operation_key: format!("module-enable:{workshop}:{module_key}:{}", operation.id),
            workshop_id: workshop,
            module_key: module_key.into(),
            modules: bundle
                .odoo_modules
                .iter()
                .map(|module| (*module).into())
                .collect(),
        })
        .await?;
    }
    if let Some(provider) = module_key.strip_prefix("shipping-") {
        sqlx::query(
            "update control.carrier_secrets set state='active',deleted_at=null
              where workshop_id=$1 and provider=$2 and state='suspended'",
        )
        .bind(workshop)
        .bind(provider)
        .execute(store.pool())
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    }
    let mut tx = tenant_store
        .begin(workshop)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    crate::workers::routes::lock_current_operation(&mut tx, operation).await?;
    let changed = sqlx::query(
        "update control.workshop_modules set state='enabled',enabled_at=now(),version=version+1
         where workshop_id=$1 and module_key=$2 and operation_id=$3 and state='installing'",
    )
    .bind(workshop)
    .bind(module_key)
    .bind(operation.id)
    .execute(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .rows_affected();
    if changed != 1 {
        return Err(IntegrationError::ContractDrift);
    }
    tx.commit()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    Ok(())
}

async fn admit_capability_restriction(store: &Store) -> anyhow::Result<()> {
    let mut tx = store.begin().await?;
    let row = sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            i64,
            Uuid,
            i32,
            Option<String>,
            Option<i64>,
            Value,
            String,
        ),
    >(
        "select wm.workshop_id,wm.module_key,wm.version,wm.requested_by,
                wm.registry_version,wm.application_release_id,wm.entitlement_version,
                wm.resolved_implementation,
                case when not exists(
                    select 1 from control.tenant_release_adoptions a
                     where a.workshop_id=wm.workshop_id and a.state='active'
                       and a.release_id=wm.application_release_id
                       and a.registry_version=wm.registry_version
                ) then 'release_drift' else 'entitlement_inactive' end
           from control.workshop_modules wm
          where wm.state='enabled' and (
            not exists(
              select 1 from control.tenant_release_adoptions a
               where a.workshop_id=wm.workshop_id and a.state='active'
                 and a.release_id=wm.application_release_id
                 and a.registry_version=wm.registry_version
            ) or not exists(
              select 1 from control.entitlements e
               where e.workshop_id=wm.workshop_id and e.version=wm.entitlement_version
                 and e.status='active' and (e.expires_at is null or e.expires_at>now())
                 and (coalesce(e.limits->'capabilities','[]'::jsonb) ? wm.module_key
                      or coalesce(e.limits->'capabilities','[]'::jsonb) ? '*')
            )
          ) order by wm.workshop_id,wm.module_key for update of wm skip locked limit 1",
    )
    .fetch_optional(&mut *tx)
    .await?;
    let Some((
        workshop,
        module_key,
        version,
        requested_by,
        registry_version,
        release_id,
        entitlement_version,
        resolved,
        reason,
    )) = row
    else {
        tx.commit().await?;
        return Ok(());
    };
    let payload = json!({
        "module_key":module_key,"reason":reason,"registry_version":registry_version,
        "application_release_id":release_id,"entitlement_version":entitlement_version,
        "resolved_implementation":resolved
    });
    let idempotency_key = format!("module-restrict:{workshop}:{module_key}:{version}:{reason}");
    let operation_id = Store::enqueue(
        &mut tx,
        crate::persistence::NewOperation {
            kind: crate::domain::OperationKind::ModuleRestrict,
            workshop_id: Some(workshop),
            target_user_id: None,
            desired_epoch: None,
            payload: &payload,
            requested_by: Some(requested_by),
            correlation_id: Uuid::new_v4(),
            idempotency_key: &idempotency_key,
        },
    )
    .await?;
    let changed = sqlx::query(
        "update control.workshop_modules set state='restricting',operation_id=$4,
                restriction_reason=$3,restriction_evidence=null,restricted_at=null,version=version+1
          where workshop_id=$1 and module_key=$2 and state='enabled' and version=$5",
    )
    .bind(workshop)
    .bind(&module_key)
    .bind(&reason)
    .bind(operation_id)
    .bind(version)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed != 1 {
        anyhow::bail!("capability restriction admission lost its row lock");
    }
    tx.commit().await?;
    tracing::info!(
        operation=%operation_id,
        reason_class=restriction_reason_class(&reason),
        "capability restriction admitted"
    );
    Ok(())
}

async fn restrict_module(
    store: &Store,
    tenant_store: &TenantStore,
    operation: &LeasedOperation,
    tenant_domain: &str,
    deployment_driver: &DeploymentDriverConfig,
) -> Result<(), IntegrationError> {
    let workshop = operation
        .workshop_id
        .ok_or(IntegrationError::ContractDrift)?;
    let module_key = operation
        .payload
        .get("module_key")
        .and_then(Value::as_str)
        .ok_or(IntegrationError::ContractDrift)?;
    let reason = operation
        .payload
        .get("reason")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 64)
        .ok_or(IntegrationError::ContractDrift)?;
    let bundle = crate::modules::bundle(module_key).ok_or(IntegrationError::ContractDrift)?;
    let pinned = sqlx::query_as::<
        _,
        (
            String,
            Option<Uuid>,
            i32,
            Option<String>,
            Option<i64>,
            Value,
            Option<String>,
            Option<Value>,
        ),
    >(
        "select state,operation_id,registry_version,application_release_id,
                entitlement_version,resolved_implementation,restriction_reason,
                restriction_evidence
           from control.workshop_modules where workshop_id=$1 and module_key=$2",
    )
    .bind(workshop)
    .bind(module_key)
    .fetch_optional(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .ok_or(IntegrationError::NotFound)?;
    if pinned.1 != Some(operation.id)
        || operation
            .payload
            .get("registry_version")
            .and_then(Value::as_i64)
            != Some(i64::from(pinned.2))
        || operation
            .payload
            .get("application_release_id")
            .and_then(Value::as_str)
            != pinned.3.as_deref()
        || operation
            .payload
            .get("entitlement_version")
            .and_then(Value::as_i64)
            != pinned.4
        || operation.payload.get("resolved_implementation") != Some(&pinned.5)
    {
        return Err(IntegrationError::ContractDrift);
    }
    if pinned.0 == "restricted" {
        if pinned.6.as_deref() == Some(reason)
            && pinned.7.as_ref().is_some_and(|value| value != &json!({}))
        {
            return Ok(());
        }
        return Err(IntegrationError::ContractDrift);
    }
    if pinned.0 != "restricting" {
        return Err(IntegrationError::ContractDrift);
    }
    let evidence = if bundle.service == Some("paperless") {
        let mut tx = tenant_store
            .begin_repeatable_read(workshop)
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        crate::workers::routes::lock_authority(&mut tx, operation).await?;
        let owned = sqlx::query_scalar::<_, bool>(
            "select exists(select 1 from control.workshop_modules
              where workshop_id=$1 and module_key=$2 and operation_id=$3
                and state='restricting' and restriction_reason=$4)",
        )
        .bind(workshop)
        .bind(module_key)
        .bind(operation.id)
        .bind(reason)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
        if !owned {
            return Err(IntegrationError::ContractDrift);
        }
        let route =
            crate::workers::routes::materialize(&mut tx, operation, tenant_domain, false).await?;
        tx.commit()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        tracing::info!(
            %workshop,
            operation=%operation.id,
            route_generation=route.generation,
            projection_digest=%route.projection_digest,
            "applying read-only Paperless route projection"
        );
        let response = crate::workers::routes::apply(
            operation,
            workshop,
            &format!("module-restrict:{module_key}:{}", operation.id),
            &route,
            deployment_driver,
        )
        .await?;
        json!({
            "adapter":"route_projection",
            "write_blocked":true,
            "historical_read_retained":true,
            "route_evidence":response.get("route_evidence")
                .ok_or(IntegrationError::ContractDrift)?
        })
    } else if !bundle.odoo_modules.is_empty() {
        let (url, secret_ref, database_ref) = service(store, workshop, "odoo").await?;
        OdooClient::new(
            &url,
            &secret(&secret_ref)?,
            database_ref.as_deref(),
            Duration::from_secs(120),
        )
        .map_err(|_| IntegrationError::ContractDrift)?
        .restrict_modules(&ModuleRestrictCommand {
            operation_key: format!("module-restrict:{workshop}:{module_key}:{}", operation.id),
            workshop_id: workshop,
            module_key: module_key.into(),
            modules: bundle
                .odoo_modules
                .iter()
                .map(|item| (*item).into())
                .collect(),
            reason: reason.into(),
        })
        .await?
    } else {
        json!({"adapter":"control_api_gate","write_blocked":true,
               "historical_read_retained":true})
    };
    if evidence.get("write_blocked").and_then(Value::as_bool) != Some(true)
        || evidence
            .get("historical_read_retained")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err(IntegrationError::ContractDrift);
    }
    let mut tx = tenant_store
        .begin(workshop)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    crate::workers::routes::lock_current_operation(&mut tx, operation).await?;
    let changed = sqlx::query(
        "update control.workshop_modules set state='restricted',restriction_evidence=$4,
                restricted_at=now(),version=version+1
          where workshop_id=$1 and module_key=$2 and operation_id=$3 and state='restricting'",
    )
    .bind(workshop)
    .bind(module_key)
    .bind(operation.id)
    .bind(evidence)
    .execute(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .rows_affected();
    if changed != 1 {
        return Err(IntegrationError::ContractDrift);
    }
    tx.commit()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    Ok(())
}

async fn enable_paperless(
    tenant_store: &TenantStore,
    operation: &LeasedOperation,
    workshop: Uuid,
    tenant_domain: &str,
    deployment_driver: &DeploymentDriverConfig,
) -> Result<(), IntegrationError> {
    let mut snapshot_tx = tenant_store
        .begin_repeatable_read(workshop)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    let tenant = sqlx::query_as::<_, (Uuid, String, String, String)>(
        "select d.id,w.slug,d.database_ref,d.public_hostname
         from control.workshops w
         join control.odoo_databases d on d.workshop_id=w.id
         where w.id=$1 and w.status<>'deleted' and d.kind='primary'
           and d.deleted_at is null and d.public_hostname is not null",
    )
    .bind(workshop)
    .fetch_optional(&mut *snapshot_tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .ok_or(IntegrationError::NotFound)?;
    let custom_hostnames = routable_custom_hostnames(&mut snapshot_tx)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    snapshot_tx
        .commit()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    let paperless_hostname = format!("docs-{}.{}", tenant.1, tenant_domain);
    let payload = json!({
        "database_id": tenant.0,
        "database_ref": tenant.2,
        "public_hostname": tenant.3,
        "paperless_hostname": paperless_hostname,
        "paperless_enabled": true,
        "custom_hostnames": custom_hostnames,
    });
    let value = driver_request(
        operation,
        workshop,
        "reconcile",
        &payload,
        deployment_driver,
    )
    .await?;
    let paperless = value
        .get("paperless")
        .ok_or(IntegrationError::ContractDrift)?;
    let mut route_tx = tenant_store
        .begin_repeatable_read(workshop)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    crate::workers::routes::lock_authority(&mut route_tx, operation).await?;
    let enabling = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.workshop_modules
          where workshop_id=$1 and module_key='documents' and operation_id=$2
            and state='installing')",
    )
    .bind(workshop)
    .bind(operation.id)
    .fetch_one(&mut *route_tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    if !enabling {
        return Err(IntegrationError::ContractDrift);
    }
    upsert_service_in_tx(&mut route_tx, workshop, "paperless", paperless, &value).await?;
    let route =
        crate::workers::routes::materialize(&mut route_tx, operation, tenant_domain, false).await?;
    route_tx
        .commit()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    tracing::info!(
        %workshop,
        operation=%operation.id,
        route_generation=route.generation,
        projection_digest=%route.projection_digest,
        "applying Paperless route projection"
    );
    crate::workers::routes::apply(
        operation,
        workshop,
        &format!("module-enable:documents:{}", operation.id),
        &route,
        deployment_driver,
    )
    .await?;

    let mut tx = tenant_store
        .begin(workshop)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    crate::workers::routes::lock_current_operation(&mut tx, operation).await?;
    let members = sqlx::query_as::<_, (Uuid, i32)>(
        "select user_id,authority_epoch from control.memberships where workshop_id=$1",
    )
    .bind(workshop)
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    for (user, epoch) in members {
        sqlx::query(
            "insert into control.membership_targets(workshop_id,user_id,target,desired_epoch)
             values($1,$2,'paperless',$3)
             on conflict(workshop_id,user_id,target) do update set
               desired_epoch=excluded.desired_epoch,state='pending',safe_error_class=null",
        )
        .bind(workshop)
        .bind(user)
        .bind(epoch)
        .execute(&mut *tx)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
        let payload = json!({"active":true});
        let key = format!("documents-enable:{workshop}:{user}:{epoch}");
        let exists = sqlx::query_scalar::<_, bool>(
            "select exists(select 1 from control.operations
             where kind='membership.reconcile' and requested_by is null and idempotency_key=$1)",
        )
        .bind(&key)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
        if !exists {
            Store::enqueue(
                tx.as_transaction(),
                crate::persistence::NewOperation {
                    kind: crate::domain::OperationKind::MembershipReconcile,
                    workshop_id: Some(workshop),
                    target_user_id: Some(user),
                    desired_epoch: Some(epoch),
                    payload: &payload,
                    requested_by: None,
                    correlation_id: Uuid::new_v4(),
                    idempotency_key: &key,
                },
            )
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        }
    }
    tx.commit()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    Ok(())
}

pub(crate) fn env(name: &str) -> Result<String, IntegrationError> {
    crate::runtime_secret::environment(name)
        .map_err(|_| IntegrationError::Unauthorized)?
        .filter(|value| !value.trim().is_empty())
        .ok_or(IntegrationError::Unauthorized)
}

pub(crate) fn configuration(name: &str) -> Result<String, IntegrationError> {
    crate::runtime_secret::required_configuration(name).map_err(|_| IntegrationError::Unauthorized)
}

fn tenant_domain(config: &WorkerConfig) -> Result<&str, IntegrationError> {
    config
        .tenant_domain()
        .ok_or(IntegrationError::ContractDrift)
}

pub(crate) fn extraction_broker(
    timeout: Duration,
) -> Result<ExtractionBrokerClient, IntegrationError> {
    ExtractionBrokerClient::new(
        &crate::runtime_secret::required_configuration("CONTROL_EXTRACTION_BROKER_URL")
            .map_err(|_| IntegrationError::Unauthorized)?,
        &env("CONTROL_EXTRACTION_BROKER_TOKEN")?,
        timeout,
    )
    .map_err(|_| IntegrationError::ContractDrift)
}
pub(crate) fn secret(reference: &str) -> Result<String, IntegrationError> {
    if reference.is_empty() || reference.len() > 180 {
        return Err(IntegrationError::ContractDrift);
    }
    let valid_reference = reference.split('/').all(|segment| {
        !segment.is_empty()
            && segment.len() <= 64
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    });
    if !valid_reference {
        return Err(IntegrationError::ContractDrift);
    }
    let root_variable = secret_root_variable(reference);
    let configured_root = crate::runtime_secret::configuration(root_variable)
        .map_err(|_| IntegrationError::Unauthorized)?;
    if let Some(root) = configured_root {
        if root.trim().is_empty() {
            return Err(IntegrationError::Unauthorized);
        }
        let root = std::fs::canonicalize(root).map_err(|_| IntegrationError::Unauthorized)?;
        let candidate = root.join(reference);
        let resolved =
            std::fs::canonicalize(&candidate).map_err(|_| IntegrationError::Unauthorized)?;
        if !resolved.starts_with(&root) {
            return Err(IntegrationError::ContractDrift);
        }
        let value = std::fs::read_to_string(resolved)
            .map_err(|_| IntegrationError::Unauthorized)?
            .trim_end_matches(['\r', '\n'])
            .to_owned();
        if value.is_empty() {
            return Err(IntegrationError::Unauthorized);
        }
        return Ok(value);
    }
    let name = format!(
        "CONTROL_SECRET__{}",
        reference
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            })
            .collect::<String>()
    );
    env(&name)
}

fn secret_root_variable(reference: &str) -> &'static str {
    if reference.ends_with("/paperless") {
        "CONTROL_PAPERLESS_SECRET_ROOT"
    } else {
        "CONTROL_SECRET_ROOT"
    }
}

pub(crate) async fn service(
    store: &Store,
    workshop: Uuid,
    name: &str,
) -> Result<(String, String, Option<String>), IntegrationError> {
    sqlx::query_as::<_, (String, String, Option<String>)>(
        "select si.base_url,si.secret_ref,od.database_ref
        from control.service_instances si
        left join control.odoo_databases od on od.workshop_id=si.workshop_id
            and od.kind='primary' and od.deleted_at is null and si.service='odoo'
        where si.workshop_id=$1 and si.service=$2",
    )
    .bind(workshop)
    .bind(name)
    .fetch_optional(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .ok_or(IntegrationError::NotFound)
}

type ServiceConnection = (String, String, Option<String>);

async fn scoped_service(
    tx: &mut WorkshopTransaction<'_>,
    name: &str,
) -> Result<ServiceConnection, IntegrationError> {
    let workshop = tx.workshop_id();
    sqlx::query_as::<_, ServiceConnection>(
        "select si.base_url,si.secret_ref,od.database_ref
        from control.service_instances si
        left join control.odoo_databases od on od.workshop_id=si.workshop_id
            and od.kind='primary' and od.deleted_at is null and si.service='odoo'
        where si.workshop_id=$1 and si.service=$2",
    )
    .bind(workshop)
    .bind(name)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .ok_or(IntegrationError::NotFound)
}

async fn membership(
    tenant_store: &TenantStore,
    workshop: Uuid,
    operation: &LeasedOperation,
) -> Result<(), IntegrationError> {
    let user = operation
        .target_user_id
        .ok_or(IntegrationError::ContractDrift)?;
    let epoch = operation
        .desired_epoch
        .ok_or(IntegrationError::ContractDrift)?;
    let mut tx = tenant_store
        .begin(workshop)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    let row=sqlx::query_as::<_,(String,Option<String>,String,String,String,i32)>("select u.email,u.display_name,i.subject,m.role,m.status,m.authority_epoch from control.users u join control.external_identities i on i.user_id=u.id join control.memberships m on m.user_id=u.id where u.id=$1 and m.workshop_id=$2")
        .bind(user).bind(workshop).fetch_optional(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?.ok_or(IntegrationError::NotFound)?;
    if row.5 != epoch {
        tx.commit()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        return Ok(());
    }
    let odoo_service = scoped_service(&mut tx, "odoo").await?;
    let has_paperless_target = sqlx::query_scalar::<_, bool>(
        "select exists(
            select 1 from control.membership_targets t
            where t.workshop_id=$1 and t.user_id=$2 and t.target='paperless'
              and (not $3 or exists(
                select 1 from control.workshop_modules m
                 where m.workshop_id=t.workshop_id and m.module_key='documents'
                   and m.state='enabled'
              ))
         )",
    )
    .bind(workshop)
    .bind(user)
    .bind(row.4 == "active")
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    let paperless_service = if has_paperless_target {
        Some(scoped_service(&mut tx, "paperless").await?)
    } else {
        None
    };
    tx.commit()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    let active = row.4 == "active";
    let rauthy = RauthyClient::new(
        &configuration("CONTROL_RAUTHY_ADMIN_URL")?,
        &env("CONTROL_RAUTHY_ADMIN_KEY")?,
        Duration::from_secs(10),
    )
    .map_err(|_| IntegrationError::ContractDrift)?;
    let rauthy_result = async {
        rauthy.observe_user(&row.2, &row.0).await?;
        if !active {
            rauthy.revoke_sessions(&row.2).await?
        }
        Ok(())
    }
    .await;
    record_target(
        tenant_store,
        workshop,
        user,
        "rauthy",
        epoch,
        &rauthy_result,
        if active { "ready" } else { "disabled" },
    )
    .await?;
    let odoo_result = async {
        let (url, reference, database_ref) = &odoo_service;
        let client = OdooClient::new(
            url,
            &secret(reference)?,
            database_ref.as_deref(),
            Duration::from_secs(20),
        )
        .map_err(|_| IntegrationError::ContractDrift)?;
        client
            .reconcile_membership(&MembershipCommand {
                operation_key: format!("membership:{workshop}:{user}:{epoch}"),
                workshop_id: workshop,
                user_id: user,
                subject: row.2.clone(),
                email: row.0.clone(),
                name: row.1.clone().unwrap_or_else(|| row.0.clone()),
                role: row.3.clone(),
                epoch,
                active,
            })
            .await?;
        Ok(())
    }
    .await;
    record_target(
        tenant_store,
        workshop,
        user,
        "odoo",
        epoch,
        &odoo_result,
        if active { "ready" } else { "disabled" },
    )
    .await?;
    let paperless_result = if let Some((url, reference, _)) = paperless_service {
        let result = async {
            let client = PaperlessClient::new(&url, &secret(&reference)?, Duration::from_secs(20))
                .map_err(|_| IntegrationError::ContractDrift)?;
            let groups = client.ensure_groups(paperless_group_names(&row.3)?).await?;
            client
                .reconcile_user(&row.2, &row.0, active, &groups, row.3 == "owner")
                .await
        }
        .await;
        record_target(
            tenant_store,
            workshop,
            user,
            "paperless",
            epoch,
            &result,
            if active { "ready" } else { "disabled" },
        )
        .await?;
        Some(result)
    } else {
        None
    };
    rauthy_result?;
    odoo_result?;
    if let Some(result) = paperless_result {
        result?;
    }
    Ok(())
}

fn paperless_group_names(role: &str) -> Result<&'static [&'static str], IntegrationError> {
    match role {
        "viewer" => Ok(&["MakersBrain Viewer"]),
        "artisan" => Ok(&["MakersBrain Artisan"]),
        "accountant" => Ok(&["MakersBrain Accountant"]),
        "studio_manager" | "owner" => Ok(&["MakersBrain Studio Manager"]),
        _ => Err(IntegrationError::ContractDrift),
    }
}

async fn record_target(
    tenant_store: &TenantStore,
    workshop: Uuid,
    user: Uuid,
    target: &str,
    epoch: i32,
    result: &Result<(), IntegrationError>,
    success: &str,
) -> Result<(), IntegrationError> {
    let (state, error) = match result {
        Ok(()) => (success, None),
        Err(error) => ("degraded", Some(error.failure_class())),
    };
    let mut tx = tenant_store
        .begin(workshop)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    sqlx::query("update control.membership_targets set applied_epoch=case when $5 is null then $4 else applied_epoch end,state=$6,safe_error_class=$5,observed_at=now() where workshop_id=$1 and user_id=$2 and target=$3 and desired_epoch=$4")
        .bind(workshop).bind(user).bind(target).bind(epoch).bind(error).bind(state).execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?;
    tx.commit()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    Ok(())
}

async fn entitlement(
    tenant_store: &TenantStore,
    workshop: Uuid,
    _operation: &LeasedOperation,
) -> Result<(), IntegrationError> {
    let mut tx = tenant_store
        .begin(workshop)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    let row=sqlx::query_as::<_,(i64,String,String,Value,Option<time::OffsetDateTime>,String)>("select version,plan,status,limits,expires_at,signature from control.entitlements where workshop_id=$1").bind(workshop).fetch_optional(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?.ok_or(IntegrationError::NotFound)?;
    let (url, reference, database_ref) = scoped_service(&mut tx, "odoo").await?;
    tx.commit()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    let client = OdooClient::new(
        &url,
        &secret(&reference)?,
        database_ref.as_deref(),
        Duration::from_secs(20),
    )
    .map_err(|_| IntegrationError::ContractDrift)?;
    client
        .apply_entitlement(&EntitlementCommand {
            operation_key: format!("entitlement:{workshop}:{}", row.0),
            workshop_id: workshop,
            version: row.0,
            plan: row.1,
            status: row.2,
            limits: row.3,
            expires_at: row.4.map(|v| v.to_string()),
            signature: row.5,
        })
        .await?;
    Ok(())
}

pub(crate) async fn driver(
    tenant_store: &TenantStore,
    operation: &LeasedOperation,
    action: &str,
    tenant_domain: &str,
    deployment_driver: &DeploymentDriverConfig,
) -> Result<Value, IntegrationError> {
    if !matches!(action, "provision" | "reconcile") {
        return Err(IntegrationError::ContractDrift);
    }
    let workshop = operation
        .workshop_id
        .ok_or(IntegrationError::ContractDrift)?;
    let value = driver_request(
        operation,
        workshop,
        action,
        &operation.payload,
        deployment_driver,
    )
    .await?;
    let mut tx = tenant_store
        .begin_repeatable_read(workshop)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    crate::workers::routes::lock_authority(&mut tx, operation).await?;
    let mut odoo_service_id = None;
    for service_name in ["odoo", "paperless"] {
        if let Some(service) = value.get(service_name) {
            let service_id =
                upsert_service_in_tx(&mut tx, workshop, service_name, service, &value).await?;
            if service_name == "odoo" {
                odoo_service_id = Some(service_id);
            }
        }
    }
    if action == "provision" {
        let expected_ref = operation
            .payload
            .get("database_ref")
            .and_then(Value::as_str)
            .ok_or(IntegrationError::ContractDrift)?;
        let expected_hostname = operation
            .payload
            .get("public_hostname")
            .and_then(Value::as_str)
            .ok_or(IntegrationError::ContractDrift)?;
        let database = value
            .get("odoo")
            .and_then(|odoo| odoo.get("database"))
            .ok_or(IntegrationError::ContractDrift)?;
        if database.get("database_ref").and_then(Value::as_str) != Some(expected_ref)
            || database.get("public_hostname").and_then(Value::as_str) != Some(expected_hostname)
            || expected_hostname == expected_ref
        {
            return Err(IntegrationError::ContractDrift);
        }
        let service_id = odoo_service_id.ok_or(IntegrationError::ContractDrift)?;
        let changed = sqlx::query("update control.odoo_databases set service_instance_id=$2,state='ready' where workshop_id=$1 and kind='primary' and database_ref=$3 and public_hostname=$4")
            .bind(workshop).bind(service_id).bind(expected_ref).bind(expected_hostname).execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?;
        if changed.rows_affected() != 1 {
            return Err(IntegrationError::ContractDrift);
        }
        let release_id = value
            .get("release_id")
            .and_then(Value::as_str)
            .ok_or(IntegrationError::ContractDrift)?;
        let database_id = sqlx::query_scalar::<_, Uuid>(
            "select id from control.odoo_databases where workshop_id=$1 and kind='primary' and database_ref=$2",
        )
        .bind(workshop)
        .bind(expected_ref)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
        sqlx::query("insert into control.tenant_release_adoptions(id,workshop_id,database_id,release_id,registry_version,state,operation_id,target_schema_epoch,started_at,verified_at,activated_at,evidence) select $1,$2,$3,r.id,(r.manifest->>'capability_registry_version')::integer,'active',$4,r.schema_epoch,now(),now(),now(),jsonb_build_object('source','tenant_provisioning','release_id',r.id,'registry_version',(r.manifest->>'capability_registry_version')::integer) from control.application_releases r join control.capability_registry_versions registry on registry.version=(r.manifest->>'capability_registry_version')::integer and registry.active where r.id=$5 and r.status='active' on conflict(workshop_id,database_id,release_id) do nothing")
            .bind(Uuid::new_v4()).bind(workshop).bind(database_id).bind(operation.id).bind(release_id).execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?;
        let adoption_recorded=sqlx::query_scalar::<_,bool>("select exists(select 1 from control.tenant_release_adoptions where workshop_id=$1 and database_id=$2 and release_id=$3 and state='active')")
            .bind(workshop).bind(database_id).bind(release_id).fetch_one(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?;
        if !adoption_recorded {
            return Err(IntegrationError::ContractDrift);
        }
    }
    let route =
        crate::workers::routes::materialize(&mut tx, operation, tenant_domain, false).await?;
    tx.commit()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    tracing::info!(
        %workshop,
        operation=%operation.id,
        action,
        route_generation=route.generation,
        projection_digest=%route.projection_digest,
        "applying converged tenant route projection"
    );
    crate::workers::routes::apply(
        operation,
        workshop,
        &format!("tenant-{action}:{}", operation.id),
        &route,
        deployment_driver,
    )
    .await?;
    if action == "provision" {
        let mut finalize = tenant_store
            .begin(workshop)
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        crate::workers::routes::lock_current_operation(&mut finalize, operation).await?;
        let status = sqlx::query_scalar::<_, String>(
            "select status from control.workshops where id=$1 for update",
        )
        .bind(workshop)
        .fetch_optional(&mut *finalize)
        .await
        .map_err(|_| IntegrationError::Unavailable)?
        .ok_or(IntegrationError::NotFound)?;
        if status == "provisioning" {
            sqlx::query(
                "update control.workshops set status='trial',version=version+1
                 where id=$1 and status='provisioning'",
            )
            .bind(workshop)
            .execute(&mut *finalize)
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        } else if status != "trial" {
            return Err(IntegrationError::ContractDrift);
        }
        let owner = sqlx::query_as::<_, (Uuid, i32)>(
            "select user_id,authority_epoch from control.memberships
             where workshop_id=$1 and role='owner' and status='active'",
        )
        .bind(workshop)
        .fetch_optional(&mut *finalize)
        .await
        .map_err(|_| IntegrationError::Unavailable)?
        .ok_or(IntegrationError::ContractDrift)?;
        seed_membership_targets(finalize.as_transaction(), workshop, owner.0, owner.1).await?;
        let payload = json!({"active":true});
        let key = format!("provision-owner:{workshop}:{}", owner.1);
        Store::enqueue(
            finalize.as_transaction(),
            crate::persistence::NewOperation {
                kind: crate::domain::OperationKind::MembershipReconcile,
                workshop_id: Some(workshop),
                target_user_id: Some(owner.0),
                desired_epoch: Some(owner.1),
                payload: &payload,
                requested_by: Some(owner.0),
                correlation_id: Uuid::new_v4(),
                idempotency_key: &key,
            },
        )
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
        finalize
            .commit()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
    }
    Ok(value)
}

async fn driver_request(
    operation: &LeasedOperation,
    workshop: Uuid,
    action: &str,
    payload: &Value,
    deployment_driver: &DeploymentDriverConfig,
) -> Result<Value, IntegrationError> {
    driver_request_with_key(
        operation,
        workshop,
        action,
        &operation.id.to_string(),
        payload,
        deployment_driver,
    )
    .await
}

pub(crate) async fn driver_request_with_key(
    operation: &LeasedOperation,
    workshop: Uuid,
    action: &str,
    idempotency_key: &str,
    payload: &Value,
    deployment_driver: &DeploymentDriverConfig,
) -> Result<Value, IntegrationError> {
    send_driver_request(
        operation.id,
        Some(operation),
        workshop,
        action,
        idempotency_key,
        payload,
        deployment_driver,
    )
    .await
}

pub(crate) async fn release_driver_request_with_key(
    operation: &LeasedOperation,
    idempotency_key: &str,
    payload: &Value,
    deployment_driver: &DeploymentDriverConfig,
) -> Result<Value, IntegrationError> {
    send_driver_request(
        operation.id,
        Some(operation),
        Uuid::nil(),
        "release",
        idempotency_key,
        payload,
        deployment_driver,
    )
    .await
}

async fn send_driver_request(
    operation_id: Uuid,
    operation_lease: Option<&LeasedOperation>,
    workshop: Uuid,
    action: &str,
    idempotency_key: &str,
    payload: &Value,
    deployment_driver: &DeploymentDriverConfig,
) -> Result<Value, IntegrationError> {
    let mut request = deployment_driver
        .client()
        .post(
            deployment_driver
                .url()
                .join(&format!("/v1/tenants/{workshop}/{action}"))
                .map_err(|_| IntegrationError::ContractDrift)?,
        )
        .header(
            reqwest::header::AUTHORIZATION,
            deployment_driver.authorization().clone(),
        )
        .header("idempotency-key", idempotency_key)
        .header("x-control-operation-id", operation_id.to_string());
    if let Some(operation) = operation_lease {
        request = request
            .header("x-control-operation-attempt", operation.attempt)
            .header(
                "x-control-operation-lease-owner",
                reqwest::header::HeaderValue::try_from(operation.leased_by.as_str())
                    .map_err(|_| IntegrationError::ContractDrift)?,
            );
    }
    let response = request
        .json(payload)
        .with_current_trace_context()
        .send()
        .await
        .map_err(|error| {
            if error.is_timeout() {
                IntegrationError::UnknownOutcome
            } else {
                IntegrationError::Unavailable
            }
        })?;
    let status = response.status();
    let value: Value = response
        .json()
        .await
        .map_err(|_| IntegrationError::ContractDrift)?;
    if !status.is_success() {
        return Err(classify_driver_response(action, status, &value));
    }
    Ok(value)
}

fn classify_driver_response(
    action: &str,
    status: reqwest::StatusCode,
    body: &Value,
) -> IntegrationError {
    if action == "release"
        && status == reqwest::StatusCode::SERVICE_UNAVAILABLE
        && body.get("error_code").and_then(Value::as_str)
            == Some("release_reconciliation_inconclusive")
    {
        IntegrationError::UnknownOutcome
    } else {
        super_classify(status)
    }
}

async fn upsert_service_in_tx(
    tx: &mut WorkshopTransaction<'_>,
    workshop: Uuid,
    service_name: &str,
    service: &Value,
    response: &Value,
) -> Result<Uuid, IntegrationError> {
    let base = service
        .get("base_url")
        .and_then(Value::as_str)
        .ok_or(IntegrationError::ContractDrift)?;
    let secret_ref = service
        .get("secret_ref")
        .and_then(Value::as_str)
        .ok_or(IntegrationError::ContractDrift)?;
    sqlx::query_scalar::<_, Uuid>("insert into control.service_instances(id,workshop_id,service,base_url,secret_ref,release_id,health,applied_epoch) values($1,$2,$3,$4,$5,$6,'ready',1) on conflict(workshop_id,service) do update set base_url=excluded.base_url,secret_ref=excluded.secret_ref,release_id=excluded.release_id,health='ready',last_observed_at=now() returning id")
        .bind(Uuid::new_v4()).bind(workshop).bind(service_name).bind(base).bind(secret_ref).bind(response.get("release_id").and_then(Value::as_str)).fetch_one(&mut **tx).await.map_err(|_|IntegrationError::Unavailable)
}

pub(crate) fn payload_uuid(payload: &Value, key: &str) -> Result<Uuid, IntegrationError> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(IntegrationError::ContractDrift)
}

async fn seed_membership_targets(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    workshop: Uuid,
    user: Uuid,
    epoch: i32,
) -> Result<(), IntegrationError> {
    sqlx::query("insert into control.membership_targets(workshop_id,user_id,target,desired_epoch)
        select $1,$2,target,$3 from unnest(array['rauthy','odoo']) target
        union all
        select $1,$2,'paperless',$3 where exists (
            select 1 from control.workshop_modules
            where workshop_id=$1 and module_key='documents' and state='enabled'
        )
        on conflict(workshop_id,user_id,target) do update set desired_epoch=excluded.desired_epoch,state='pending',safe_error_class=null")
        .bind(workshop).bind(user).bind(epoch).execute(&mut **tx).await.map_err(|_| IntegrationError::Unavailable)?;
    Ok(())
}

fn deployment_driver(config: &WorkerConfig) -> Result<&DeploymentDriverConfig, IntegrationError> {
    config
        .deployment_driver()
        .ok_or(IntegrationError::ContractDrift)
}

fn restriction_reason_class(reason: &str) -> &'static str {
    match reason {
        "release_drift" => "release_drift",
        "entitlement_inactive" => "entitlement_inactive",
        _ => "unknown",
    }
}

fn operation_kind_class(kind: &str) -> &'static str {
    match kind {
        "tenant.provision" => "tenant.provision",
        "membership.reconcile" => "membership.reconcile",
        "entitlement.apply" => "entitlement.apply",
        "invoice.capture" => "invoice.capture",
        "inventory.capture.extract" => "inventory.capture.extract",
        "tenant.reconcile" => "tenant.reconcile",
        "tenant.lifecycle" => "tenant.lifecycle",
        "email.delivery" => "email.delivery",
        "module.enable" => "module.enable",
        "module.restrict" => "module.restrict",
        "odoo.release.adopt" => "odoo.release.adopt",
        "privacy.retention" => "privacy.retention",
        "privacy.data_subject_request" => "privacy.data_subject_request",
        "webshop-domain.reconcile" => "webshop-domain.reconcile",
        "webshop-email-domain.reconcile" => "webshop-email-domain.reconcile",
        "webshop-onboarding.reconcile" => "webshop-onboarding.reconcile",
        _ => "unknown",
    }
}

fn release_failure_is_terminal(error: IntegrationError, attempt: i32, max_attempts: i32) -> bool {
    !matches!(error, IntegrationError::UnknownOutcome)
        && (!error.retryable() || attempt >= max_attempts)
}

fn domain_failure_is_terminal(error: IntegrationError, attempt: i32, max_attempts: i32) -> bool {
    !matches!(error, IntegrationError::UnknownOutcome)
        && (!error.retryable() || attempt >= max_attempts)
}

async fn mark_module_activation_failed(
    store: &Store,
    operation: &LeasedOperation,
    workshop: Uuid,
    module_key: &str,
) -> Result<(), IntegrationError> {
    let mut tx = store
        .begin()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    if !lock_current_operation_lease(&mut tx, operation)
        .await
        .map_err(|_| IntegrationError::Unavailable)?
    {
        return Err(IntegrationError::UnknownOutcome);
    }
    let state = sqlx::query_scalar::<_, String>(
        "select state from control.workshop_modules
          where workshop_id=$1 and module_key=$2 and operation_id=$3
          for update",
    )
    .bind(workshop)
    .bind(module_key)
    .bind(operation.id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .ok_or(IntegrationError::ContractDrift)?;
    if matches!(state.as_str(), "requested" | "installing") {
        let changed = sqlx::query(
            "update control.workshop_modules set state='failed',version=version+1
              where workshop_id=$1 and module_key=$2 and operation_id=$3
                and state in ('requested','installing')",
        )
        .bind(workshop)
        .bind(module_key)
        .bind(operation.id)
        .execute(&mut *tx)
        .await
        .map_err(|_| IntegrationError::Unavailable)?
        .rows_affected();
        if changed != 1 {
            return Err(IntegrationError::UnknownOutcome);
        }
    } else if state != "failed" {
        return Err(IntegrationError::ContractDrift);
    }
    tx.commit().await.map_err(|_| IntegrationError::Unavailable)
}

fn log_operation_result(operation: &LeasedOperation, result: &Result<(), IntegrationError>) {
    match result {
        Ok(()) => {
            tracing::info!(
                operation=%operation.id,
                outcome="succeeded",
                "durable operation completed"
            );
        }
        Err(error) => {
            tracing::warn!(
                operation=%operation.id,
                outcome=if matches!(error, IntegrationError::UnknownOutcome) {
                    "unknown"
                } else if error.retryable() {
                    "retry"
                } else {
                    "failed"
                },
                failure_class=crate::error_reporting::safe_error_class(error),
                retryable=error.retryable(),
                attempt=operation.attempt,
                max_attempts=operation.max_attempts,
                "durable operation completed"
            );
        }
    }
}
fn super_classify(status: reqwest::StatusCode) -> IntegrationError {
    match status.as_u16() {
        400 | 409 | 422 => IntegrationError::Rejected,
        401 | 403 => IntegrationError::Unauthorized,
        404 => IntegrationError::NotFound,
        429 => IntegrationError::RateLimited {
            retry_after_seconds: None,
        },
        500..=599 => IntegrationError::Unavailable,
        _ => IntegrationError::ContractDrift,
    }
}

#[cfg(test)]
mod tests {
    use std::future::pending;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use tracing::field::{Field, Visit};
    use tracing::{Event, Subscriber};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt as _;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    #[test]
    fn exact_release_reconciliation_code_preserves_unknown_outcome() {
        let body = json!({"error_code":"release_reconciliation_inconclusive"});
        assert_eq!(
            classify_driver_response("release", reqwest::StatusCode::SERVICE_UNAVAILABLE, &body),
            IntegrationError::UnknownOutcome
        );
    }

    #[test]
    fn reconciliation_code_is_scoped_to_release_and_exact_status() {
        let body = json!({"error_code":"release_reconciliation_inconclusive"});
        assert_eq!(
            classify_driver_response("provision", reqwest::StatusCode::SERVICE_UNAVAILABLE, &body),
            IntegrationError::Unavailable
        );
        assert_eq!(
            classify_driver_response("release", reqwest::StatusCode::CONFLICT, &body),
            IntegrationError::Rejected
        );
        assert_eq!(
            classify_driver_response(
                "release",
                reqwest::StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error_code":"release_reconciliation_inconclusive_v2"}),
            ),
            IntegrationError::Unavailable
        );
    }

    #[derive(Clone, Default)]
    struct RecordedEvents(Arc<Mutex<Vec<String>>>);

    struct EventVisitor<'a>(&'a mut String);

    impl Visit for EventVisitor<'_> {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write as _;
            let _ = write!(self.0, "{}={value:?};", field.name());
        }
    }

    impl<S: Subscriber> Layer<S> for RecordedEvents {
        fn on_event(&self, event: &Event<'_>, _context: tracing_subscriber::layer::Context<'_, S>) {
            let mut rendered = String::new();
            event.record(&mut EventVisitor(&mut rendered));
            self.0.lock().expect("recorded event lock").push(rendered);
        }
    }

    struct DropNotification(Option<tokio::sync::oneshot::Sender<()>>);

    impl Drop for DropNotification {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    #[tokio::test]
    async fn lease_loss_cancels_the_handler_before_terminal_work() {
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        let terminal_work = Arc::new(AtomicUsize::new(0));
        let terminal_work_in_handler = terminal_work.clone();
        let handler = async move {
            let _drop_notification = DropNotification(Some(dropped_tx));
            pending::<()>().await;
            terminal_work_in_handler.fetch_add(1, Ordering::SeqCst);
        };

        let guarded = guard_operation_lease(handler, Duration::from_millis(1), || async {
            Ok::<bool, &'static str>(false)
        })
        .await
        .unwrap();

        assert_eq!(guarded, GuardedOperation::LeaseLost);
        dropped_rx.await.expect("handler future must be dropped");
        assert_eq!(terminal_work.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn handler_completion_cancels_the_structured_heartbeat() {
        let renewals = Arc::new(AtomicUsize::new(0));
        let renewals_for_heartbeat = renewals.clone();
        let guarded =
            guard_operation_lease(async { "completed" }, Duration::from_millis(1), move || {
                let renewals = renewals_for_heartbeat.clone();
                async move {
                    renewals.fetch_add(1, Ordering::SeqCst);
                    Ok::<bool, &'static str>(true)
                }
            })
            .await
            .unwrap();

        assert_eq!(guarded, GuardedOperation::Completed("completed"));
        tokio::time::sleep(Duration::from_millis(3)).await;
        assert_eq!(renewals.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn heartbeat_error_cancels_the_handler() {
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        let handler = async move {
            let _drop_notification = DropNotification(Some(dropped_tx));
            pending::<()>().await
        };
        let error = guard_operation_lease(handler, Duration::from_millis(1), || async {
            Err::<bool, &'static str>("database_unavailable")
        })
        .await
        .unwrap_err();

        assert_eq!(error, "database_unavailable");
        dropped_rx.await.expect("handler future must be dropped");
    }

    #[tokio::test]
    async fn non_release_driver_requests_carry_the_exact_worker_lease_tuple() {
        let server = MockServer::start().await;
        let workshop = Uuid::new_v4();
        let operation = LeasedOperation {
            id: Uuid::new_v4(),
            kind: "webshop-domain.reconcile".into(),
            workshop_id: Some(workshop),
            target_user_id: None,
            desired_epoch: None,
            payload: json!({}),
            attempt: 7,
            max_attempts: 12,
            leased_by: "tenant-reconciliation-worker-a".into(),
            reconciling: false,
            trace_parent: None,
            trace_state: None,
        };
        let payload = json!({"route_projection":"test"});
        let idempotency_key = format!("worker-driver-lease:{}", operation.id);
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{workshop}/reconcile")))
            .and(header("authorization", "Bearer test-driver"))
            .and(header("idempotency-key", idempotency_key.as_str()))
            .and(header("x-control-operation-id", operation.id.to_string()))
            .and(header(
                "x-control-operation-attempt",
                operation.attempt.to_string(),
            ))
            .and(header(
                "x-control-operation-lease-owner",
                operation.leased_by.as_str(),
            ))
            .and(body_json(&payload))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"accepted":true})))
            .expect(1)
            .mount(&server)
            .await;

        let response = driver_request_with_key(
            &operation,
            workshop,
            "reconcile",
            &idempotency_key,
            &payload,
            &DeploymentDriverConfig::for_test(&server.uri()),
        )
        .await
        .unwrap();
        assert_eq!(response, json!({"accepted":true}));
    }

    #[test]
    fn worker_driver_call_sites_cannot_bypass_the_leased_operation_transport() {
        let worker = include_str!("worker.rs");
        let production = worker.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains(
            "pub(crate) async fn driver_request_with_key(\n    operation: &LeasedOperation,"
        ));
        assert!(production.contains("async fn driver_request(\n    operation: &LeasedOperation,"));
        assert_eq!(
            production.matches("send_driver_request(").count(),
            3,
            "only the two LeasedOperation wrappers may call the private transport"
        );
        assert_eq!(
            production.matches("/v1/tenants/").count(),
            1,
            "worker deployment-driver HTTP must remain centralized"
        );
        for source in [
            include_str!("workers/domains.rs"),
            include_str!("workers/lifecycle.rs"),
            include_str!("workers/release.rs"),
        ] {
            let production = source.split("#[cfg(test)]").next().unwrap();
            assert!(
                !production.contains("/v1/tenants/"),
                "feature workers must use the typed deployment-driver transport"
            );
        }
    }

    #[test]
    fn periodic_fleet_admission_stays_behind_bounded_database_capabilities() {
        let worker = include_str!("worker.rs");
        let production = worker.split("#[cfg(test)]").next().unwrap();
        for function in [
            "admit_due_webshop_domain_reconciliations($1,$2,$3)",
            "admit_due_webshop_email_domain_reconciliations($1,$2,$3)",
            "admit_due_tenant_reconciliations($1,$2,$3,$4)",
        ] {
            assert!(
                production.contains(function),
                "periodic admission must use {function}"
            );
        }
        assert!(!production.contains("select id,workshop_id from control.webshop_email_domains"));
        assert!(!production.contains("select w.id,d.id,w.slug,d.database_ref"));
    }

    #[test]
    fn durable_outcome_logs_exclude_operation_payload_and_worker_metadata() {
        const TOKEN: &str = "Bearer worker-log-canary";
        const EMAIL: &str = "private-subject@example.test";
        const HOSTNAME: &str = "private-tenant.example.test";
        const PAYLOAD: &str = "private invoice payload";
        const SECRET_PATH: &str = "/run/secrets/private-worker-key";
        let operation_id = Uuid::new_v4();
        let operation = LeasedOperation {
            id: operation_id,
            kind: "tenant.reconcile".into(),
            workshop_id: Some(Uuid::new_v4()),
            target_user_id: Some(Uuid::new_v4()),
            desired_epoch: Some(7),
            payload: json!({
                "authorization": TOKEN,
                "email": EMAIL,
                "hostname": HOSTNAME,
                "document": PAYLOAD,
                "secret_path": SECRET_PATH,
            }),
            attempt: 2,
            max_attempts: 5,
            leased_by: EMAIL.into(),
            reconciling: false,
            trace_parent: None,
            trace_state: Some(TOKEN.into()),
        };
        let recorded = RecordedEvents::default();
        let subscriber = tracing_subscriber::registry().with(recorded.clone());

        tracing::subscriber::with_default(subscriber, || {
            log_operation_result(&operation, &Err(IntegrationError::Unauthorized));
        });

        let rendered = recorded.0.lock().expect("recorded event lock").join("\n");
        assert!(rendered.contains(&operation_id.to_string()));
        assert!(rendered.contains("unauthorized"));
        assert!(rendered.contains("retryable=false"));
        for sensitive in [TOKEN, EMAIL, HOSTNAME, PAYLOAD, SECRET_PATH] {
            assert!(
                !rendered.contains(sensitive),
                "captured worker log leaked {sensitive}"
            );
        }
    }

    #[test]
    fn restriction_log_reason_is_closed() {
        assert_eq!(restriction_reason_class("release_drift"), "release_drift");
        assert_eq!(
            restriction_reason_class("subject@example.test Bearer secret"),
            "unknown"
        );
        assert_eq!(operation_kind_class("tenant.reconcile"), "tenant.reconcile");
        assert_eq!(
            operation_kind_class("private-subject@example.test"),
            "unknown"
        );
    }

    #[test]
    fn unknown_release_outcomes_are_never_collapsed_into_terminal_failure() {
        assert!(!release_failure_is_terminal(
            IntegrationError::UnknownOutcome,
            3,
            3
        ));
        assert!(!release_failure_is_terminal(
            IntegrationError::Unavailable,
            2,
            3
        ));
        assert!(release_failure_is_terminal(
            IntegrationError::Unavailable,
            3,
            3
        ));
        assert!(release_failure_is_terminal(
            IntegrationError::Rejected,
            1,
            3
        ));
    }

    #[test]
    fn unknown_domain_outcomes_are_never_collapsed_into_terminal_failure() {
        assert!(!domain_failure_is_terminal(
            IntegrationError::UnknownOutcome,
            12,
            12
        ));
        assert!(!domain_failure_is_terminal(
            IntegrationError::Unavailable,
            11,
            12
        ));
        assert!(domain_failure_is_terminal(
            IntegrationError::Unavailable,
            12,
            12
        ));
        assert!(domain_failure_is_terminal(
            IntegrationError::Rejected,
            1,
            12
        ));
    }

    #[test]
    fn leased_operations_are_validated_before_dispatch() {
        let workshop = Uuid::new_v4();
        let operation = |kind: &str, workshop_id| LeasedOperation {
            id: Uuid::new_v4(),
            kind: kind.to_owned(),
            workshop_id,
            target_user_id: None,
            desired_epoch: None,
            payload: json!({}),
            attempt: 1,
            max_attempts: 3,
            leased_by: "scope-test-worker".into(),
            reconciling: false,
            trace_parent: None,
            trace_state: None,
        };

        let tenant = operation("membership.reconcile", Some(workshop));
        assert!(matches!(
            validate_operation("membership-provisioning", &tenant),
            Ok(ValidatedOperation::Workshop {
                kind: OperationKind::MembershipReconcile,
                workshop_id,
                ..
            }) if workshop_id == workshop
        ));
        assert!(validate_operation("privacy-operations", &tenant).is_err());
        assert!(
            validate_operation(
                "membership-provisioning",
                &operation("membership.reconcile", None)
            )
            .is_err()
        );
        assert!(
            validate_operation(
                "membership-provisioning",
                &operation("membership.reconcile", Some(Uuid::nil()))
            )
            .is_err()
        );
        assert!(
            validate_operation(
                "release-adoption",
                &operation("odoo.release.adopt", Some(workshop))
            )
            .is_err()
        );
        assert!(matches!(
            validate_operation("release-adoption", &operation("odoo.release.adopt", None)),
            Ok(ValidatedOperation::Fleet {
                kind: OperationKind::OdooReleaseAdopt,
                ..
            })
        ));
        assert!(
            validate_operation(
                "tenant-lifecycle",
                &operation("private.operation", Some(workshop))
            )
            .is_err()
        );
    }

    #[tokio::test]
    #[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
    async fn an_expired_operation_lease_cannot_be_resurrected() {
        let url = std::env::var("CONTROL_TEST_DATABASE_URL")
            .expect("CONTROL_TEST_DATABASE_URL for disposable PostgreSQL");
        let store = Store::connect(&url).await.expect("connect test PostgreSQL");
        store.migrate().await.expect("migrate test PostgreSQL");
        let operation = Uuid::new_v4();
        let owner = format!("lease-expiry-test-{}", Uuid::new_v4());
        sqlx::query(
            "insert into control.operations(
                id,kind,queue,payload,correlation_id,idempotency_key,state,
                attempt,leased_by,lease_expires_at
             ) values($1,'privacy.retention','privacy-operations','{}',$2,$3,
                'in_flight',3,$4,now()-interval '1 second')",
        )
        .bind(operation)
        .bind(Uuid::new_v4())
        .bind(format!("expired-lease:{operation}"))
        .bind(&owner)
        .execute(store.pool())
        .await
        .unwrap();
        let before = sqlx::query_scalar::<_, time::OffsetDateTime>(
            "select lease_expires_at from control.operations where id=$1",
        )
        .bind(operation)
        .fetch_one(store.pool())
        .await
        .unwrap();
        let stale = LeasedOperation {
            id: operation,
            kind: "privacy.retention".into(),
            workshop_id: None,
            target_user_id: None,
            desired_epoch: None,
            payload: json!({}),
            attempt: 3,
            max_attempts: 5,
            leased_by: owner.clone(),
            reconciling: false,
            trace_parent: None,
            trace_state: None,
        };

        assert!(!store.renew_lease(operation, &owner, 3).await.unwrap());
        assert!(
            store
                .save_operation_checkpoint(&stale, &json!({"phase":"stale"}))
                .await
                .is_err()
        );
        assert!(
            store
                .finish(&stale, OperationOutcome::Succeeded)
                .await
                .is_err()
        );
        let after = sqlx::query_scalar::<_, time::OffsetDateTime>(
            "select lease_expires_at from control.operations where id=$1",
        )
        .bind(operation)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(after, before);
        let state = sqlx::query_as::<_, (String, Option<Value>)>(
            "select state,checkpoint from control.operations where id=$1",
        )
        .bind(operation)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(state, ("in_flight".into(), None));

        let new_owner = format!("lease-takeover-test-{}", Uuid::new_v4());
        sqlx::query(
            "update control.operations set attempt=4,leased_by=$2,
                lease_expires_at=now()+interval '60 seconds' where id=$1",
        )
        .bind(operation)
        .bind(&new_owner)
        .execute(store.pool())
        .await
        .unwrap();
        assert!(
            store
                .finish(&stale, OperationOutcome::Succeeded)
                .await
                .is_err()
        );
        let current = LeasedOperation {
            attempt: 4,
            leased_by: new_owner,
            reconciling: true,
            ..stale
        };
        store
            .finish(&current, OperationOutcome::Succeeded)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
    async fn terminal_cleanup_lock_serializes_expired_lease_takeover() {
        let url = std::env::var("CONTROL_TEST_DATABASE_URL")
            .expect("CONTROL_TEST_DATABASE_URL for disposable PostgreSQL");
        let store = Store::connect(&url).await.expect("connect test PostgreSQL");
        store.migrate().await.expect("migrate test PostgreSQL");
        let operation_id = Uuid::new_v4();
        let queue = format!("lease-cleanup-race-{operation_id}");
        let stale_owner = format!("lease-cleanup-owner-{}", Uuid::new_v4());
        sqlx::query(
            "insert into control.operations(
                id,kind,queue,payload,correlation_id,idempotency_key,state,
                attempt,leased_by,lease_expires_at
             ) values($1,'privacy.retention',$2,'{}',$3,$4,
                'in_flight',3,$5,clock_timestamp()+interval '250 milliseconds')",
        )
        .bind(operation_id)
        .bind(&queue)
        .bind(Uuid::new_v4())
        .bind(format!("cleanup-lock-race:{operation_id}"))
        .bind(&stale_owner)
        .execute(store.pool())
        .await
        .unwrap();
        let stale = LeasedOperation {
            id: operation_id,
            kind: "privacy.retention".into(),
            workshop_id: None,
            target_user_id: None,
            desired_epoch: None,
            payload: json!({}),
            attempt: 3,
            max_attempts: 5,
            leased_by: stale_owner,
            reconciling: false,
            trace_parent: None,
            trace_state: None,
        };

        let mut cleanup = store.begin().await.unwrap();
        assert!(
            lock_current_operation_lease(&mut cleanup, &stale)
                .await
                .unwrap(),
            "terminal cleanup must acquire the original live authority"
        );
        tokio::time::sleep(Duration::from_millis(400)).await;

        let claimant_owner = format!("lease-cleanup-claimant-{}", Uuid::new_v4());
        assert!(
            tokio::time::timeout(Duration::from_secs(2), store.lease(&queue, &claimant_owner),)
                .await
                .expect("the claimant query must remain responsive")
                .unwrap()
                .is_none(),
            "skip-locked takeover must not claim a row held by terminal cleanup"
        );

        sqlx::query(
            "update control.operations set progress_phase='terminal_cleanup_recorded'
             where id=$1",
        )
        .bind(operation_id)
        .execute(&mut *cleanup)
        .await
        .unwrap();
        cleanup.commit().await.unwrap();

        let claimed =
            tokio::time::timeout(Duration::from_secs(2), store.lease(&queue, &claimant_owner))
                .await
                .expect("takeover must finish after cleanup commits")
                .unwrap()
                .expect("the expired operation must be reclaimed");
        assert_eq!(claimed.id, operation_id);
        assert_eq!(claimed.attempt, 4);
        assert!(claimed.reconciling);
        assert_eq!(claimed.leased_by, claimant_owner);
        let progress_phase = sqlx::query_scalar::<_, Option<String>>(
            "select progress_phase from control.operations where id=$1",
        )
        .bind(operation_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(progress_phase.as_deref(), Some("terminal_cleanup_recorded"));

        let mut stale_check = store.begin().await.unwrap();
        assert!(
            !lock_current_operation_lease(&mut stale_check, &stale)
                .await
                .unwrap(),
            "the original attempt must not regain authority after takeover"
        );
        stale_check.rollback().await.unwrap();
        store
            .finish(&claimed, OperationOutcome::Succeeded)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
    async fn terminal_disconnect_failure_is_admitted_again() {
        let url = std::env::var("CONTROL_TEST_DATABASE_URL")
            .expect("CONTROL_TEST_DATABASE_URL for disposable PostgreSQL");
        let store = Store::connect(&url).await.expect("connect test PostgreSQL");
        store.migrate().await.expect("migrate test PostgreSQL");
        let user = Uuid::new_v4();
        let workshop = Uuid::new_v4();
        let domain = Uuid::new_v4();
        sqlx::query("insert into control.users(id,email) values($1,$2)")
            .bind(user)
            .bind(format!("{user}@example.test"))
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query("insert into control.workshops(id,slug,display_name,time_zone) values($1,$2,'Disconnect retry fixture','Europe/Paris')")
            .bind(workshop)
            .bind(format!("disconnect-retry-{}", workshop.simple()))
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query("insert into control.webshop_domains(id,workshop_id,hostname,verification_name,verification_value,routing_target,state,desired_state,last_error_class,redirect_target,created_by) values($1,$2,$3,$4,$5,'shops.makersbrain.com','action_required','disconnected','reconciliation_failed','platform.example.test',$6)")
            .bind(domain)
            .bind(workshop)
            .bind(format!("{}.example.test", domain.simple()))
            .bind(format!("_mb-challenge.{}.example.test", domain.simple()))
            .bind(format!("mb-verification={}", &domain.simple().to_string()[..32]))
            .bind(user)
            .execute(store.pool())
            .await
            .unwrap();

        assert_eq!(
            admit_webshop_domain_reconciliation(&store).await.unwrap(),
            1
        );
        let admitted = sqlx::query_as::<_, (String, String, Value)>(
            "select o.kind,o.state,o.payload from control.webshop_domains d
               join control.operations o on o.id=d.operation_id where d.id=$1",
        )
        .bind(domain)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(
            (admitted.0, admitted.1),
            ("webshop-domain.reconcile".into(), "pending".into())
        );
        assert_eq!(
            admitted
                .2
                .get("restore_platform_canonical")
                .and_then(Value::as_bool),
            Some(true)
        );
    }

    #[tokio::test]
    #[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
    async fn terminal_email_domain_disconnect_is_admitted_again() {
        let url = std::env::var("CONTROL_TEST_DATABASE_URL")
            .expect("CONTROL_TEST_DATABASE_URL for disposable PostgreSQL");
        let store = Store::connect(&url).await.expect("connect test PostgreSQL");
        store.migrate().await.expect("migrate test PostgreSQL");
        let user = Uuid::new_v4();
        let workshop = Uuid::new_v4();
        let domain = Uuid::new_v4();
        sqlx::query("insert into control.users(id,email) values($1,$2)")
            .bind(user)
            .bind(format!("{user}@example.test"))
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query("insert into control.workshops(id,slug,display_name,time_zone) values($1,$2,'Email disconnect retry fixture','Europe/Paris')")
            .bind(workshop)
            .bind(format!("email-disconnect-retry-{}", workshop.simple()))
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query("insert into control.webshop_email_domains(id,workshop_id,domain_name,state,desired_state,last_error_class,created_by) values($1,$2,$3,'action_required','disconnected','reconciliation_failed',$4)")
            .bind(domain)
            .bind(workshop)
            .bind(format!("{}.example.test", domain.simple()))
            .bind(user)
            .execute(store.pool())
            .await
            .unwrap();

        assert_eq!(
            admit_webshop_email_domain_reconciliation(&store)
                .await
                .unwrap(),
            1
        );
        let admitted = sqlx::query_as::<_, (String, String)>(
            "select o.kind,o.state from control.webshop_email_domains d
               join control.operations o on o.id=d.operation_id where d.id=$1",
        )
        .bind(domain)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(
            admitted,
            ("webshop-email-domain.reconcile".into(), "pending".into())
        );
    }

    #[test]
    fn secret_names_cannot_escape_environment_namespace() {
        assert_eq!(
            "CONTROL_SECRET__TENANTS_DEMO_ODOO",
            format!(
                "CONTROL_SECRET__{}",
                "tenants/demo/odoo"
                    .chars()
                    .map(|c| if c.is_ascii_alphanumeric() {
                        c.to_ascii_uppercase()
                    } else {
                        '_'
                    })
                    .collect::<String>()
            )
        );
    }
    #[test]
    fn paperless_credentials_use_the_dedicated_client_root() {
        assert_eq!(
            secret_root_variable("docker/00000000-0000-0000-0000-000000000000/paperless"),
            "CONTROL_PAPERLESS_SECRET_ROOT"
        );
        assert_eq!(
            secret_root_variable("docker/00000000-0000-0000-0000-000000000000/odoo"),
            "CONTROL_SECRET_ROOT"
        );
    }
    #[test]
    fn pdf_page_estimate_is_bounded_below() {
        assert_eq!(
            crate::workers::extraction::estimated_pages(b"not a pdf", "application/pdf"),
            1
        );
    }
    #[test]
    fn resolved_lot_crop_does_not_spend_a_multimodal_call() {
        assert!(!crate::workers::extraction::inventory_needs_vision(
            true, false, true
        ));
        assert!(crate::workers::extraction::inventory_needs_vision(
            true, false, false
        ));
        assert!(crate::workers::extraction::inventory_needs_vision(
            false, false, true
        ));
        assert!(!crate::workers::extraction::inventory_needs_vision(
            false, true, true
        ));
    }
}
