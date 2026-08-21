use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use tracing::Instrument as _;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use uuid::Uuid;

use crate::domain::{IntegrationError, OperationKind};
use crate::integrations::extraction::ExtractionBrokerClient;
use crate::integrations::odoo::{
    EntitlementCommand, MembershipCommand, ModuleEnableCommand, ModuleRestrictCommand, OdooClient,
};
use crate::integrations::paperless::PaperlessClient;
use crate::integrations::rauthy::RauthyClient;
use crate::persistence::{LeasedOperation, NewOperation, OperationOutcome, Store};
use crate::privacy_crypto;

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

pub(crate) async fn routable_custom_hostnames(
    store: &Store,
    workshop: Uuid,
) -> Result<Value, sqlx::Error> {
    sqlx::query_scalar::<_, Value>(
        "select coalesce(jsonb_agg(jsonb_build_object(
                    'hostname',hostname,'canonical',canonical) order by hostname),'[]'::jsonb)
           from control.webshop_domains
          where workshop_id=$1 and state in ('testing','active') and desired_state='active'",
    )
    .bind(workshop)
    .fetch_one(store.pool())
    .await
}

pub async fn run(store: Store, queue: &str) -> anyhow::Result<()> {
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
    let release_id = std::env::var("CONTROL_RELEASE_ID")
        .ok()
        .filter(|value| {
            (1..=200).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_graphic())
        })
        .ok_or_else(|| {
            anyhow::anyhow!("CONTROL_RELEASE_ID must name the immutable control image release")
        })?;
    store.start_worker(&worker_id, queue, &release_id).await?;
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
                        let admitted = admit_periodic_tenant_reconciliation(&store).await?;
                        tracing::info!(admitted,"admitted periodic tenant reconciliation operations");
                        next_tenant_reconciliation = Instant::now() + TENANT_RECONCILIATION_INTERVAL;
                    }
                }
                if queue == "privacy-operations" && Instant::now() >= next_privacy_export_cleanup {
                    let deleted = crate::workers::privacy::cleanup_export_artifacts(&store)
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
                    let heartbeat_store = store.clone();
                    let heartbeat_operation_id = operation.id;
                    let heartbeat_worker = operation.leased_by.clone();
                    let heartbeat_attempt = operation.attempt;
                    let heartbeat = tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(Duration::from_secs(20)).await;
                            match heartbeat_store.renew_lease(heartbeat_operation_id, &heartbeat_worker, heartbeat_attempt).await {
                                Ok(true) => {
                                    if let Err(error)=heartbeat_store.heartbeat_worker(&heartbeat_worker,Some(heartbeat_operation_id)).await {
                                        tracing::warn!(operation=%heartbeat_operation_id,error=%error,"worker heartbeat failed");
                                    }
                                }
                                Ok(false) => break,
                                Err(error) => tracing::warn!(operation=%heartbeat_operation_id,error=%error,"operation lease heartbeat failed"),
                            }
                        }
                    });
                    let span = tracing::info_span!(
                        "durable_operation",
                        operation_id = %operation.id,
                        operation_kind = %operation.kind,
                        attempt = operation.attempt,
                        reconciling = operation.reconciling
                    );
                    if let Some(trace_parent) = operation.trace_parent.as_deref() {
                        let mut carrier = std::collections::HashMap::from([(
                            "traceparent".to_owned(),
                            trace_parent.to_owned(),
                        )]);
                        if let Some(trace_state) = operation.trace_state.as_deref() {
                            carrier.insert("tracestate".to_owned(), trace_state.to_owned());
                        }
                        let parent = opentelemetry::global::get_text_map_propagator(|propagator| {
                            propagator.extract(&carrier)
                        });
                        if span.set_parent(parent).is_err() {
                            tracing::warn!(
                                error_class = "trace_parent_rejected",
                                "durable operation trace context was not attached"
                            );
                        }
                    }
                    let result = handle(&store,&operation).instrument(span).await;
                    if operation.kind == "tenant.lifecycle"
                        && result.as_ref().is_err_and(|error| !error.retryable() || operation.attempt >= operation.max_attempts)
                    {
                        crate::workers::lifecycle::failed(&store, &operation).await;
                    }
                    if operation.kind == "odoo.release.adopt"
                        && result.as_ref().is_err_and(|error| !error.retryable() || operation.attempt >= operation.max_attempts)
                    {
                        crate::workers::release::failed(&store, &operation).await;
                    }
                    if operation.kind == "webshop-onboarding.reconcile"
                        && result.as_ref().is_err_and(|error| !error.retryable() || operation.attempt >= operation.max_attempts)
                    {
                        crate::workers::onboarding::failed(&store, &operation).await;
                    }
                    if operation.kind == "webshop-domain.reconcile"
                        && result.as_ref().is_err_and(|error| !error.retryable() || operation.attempt >= operation.max_attempts)
                    {
                        crate::workers::domains::failed(&store, &operation).await;
                    }
                    if operation.kind == "webshop-email-domain.reconcile"
                        && result.as_ref().is_err_and(|error| !error.retryable() || operation.attempt >= operation.max_attempts)
                    {
                        crate::workers::email_domains::failed(&store, &operation).await;
                    }
                    if operation.kind == "module.enable"
                        && result.as_ref().is_err_and(|error| !error.retryable() || operation.attempt >= operation.max_attempts)
                        && let (Some(workshop),Some(module_key))=(operation.workshop_id,operation.payload.get("module_key").and_then(Value::as_str))
                        && let Err(error)=sqlx::query("update control.workshop_modules set state='failed',version=version+1 where workshop_id=$1 and module_key=$2 and operation_id=$3 and state in ('requested','installing')")
                            .bind(workshop).bind(module_key).bind(operation.id).execute(store.pool()).await
                    {
                        tracing::error!(operation=%operation.id,error=%error,"could not mark capability activation failed");
                    }
                    let outcome=match result{
                        Ok(())=>OperationOutcome::Succeeded,
                        Err(IntegrationError::UnknownOutcome)=>OperationOutcome::Unknown,
                        Err(error) if error.retryable()=>OperationOutcome::Retry(error),
                        Err(error)=>OperationOutcome::Failed(error),
                    };
                    heartbeat.abort();
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
    let bucket = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / WEBSHOP_EMAIL_DOMAIN_RECONCILIATION_INTERVAL.as_secs();
    let rows=sqlx::query_as::<_,(Uuid,Uuid)>("select id,workshop_id from control.webshop_email_domains d where ((desired_state='active' and state in ('registering','dns_pending','testing')) or (desired_state='disconnected' and state in ('disconnecting','action_required'))) and not exists(select 1 from control.operations o where o.id=d.operation_id and o.state in ('pending','in_flight','awaiting_reconciliation')) order by id limit 500").fetch_all(store.pool()).await?;
    let mut admitted = 0;
    for (id, workshop) in rows {
        let mut tx = store.begin().await?;
        let operation = Store::enqueue(
            &mut tx,
            NewOperation {
                kind: OperationKind::WebshopEmailDomainReconcile,
                workshop_id: Some(workshop),
                target_user_id: None,
                desired_epoch: None,
                payload: &json!({"email_domain_id":id,"reason":"periodic_observation"}),
                requested_by: None,
                correlation_id: Uuid::new_v4(),
                idempotency_key: &format!("periodic-email-domain:{id}:{bucket}"),
            },
        )
        .await?;
        let changed=sqlx::query("update control.webshop_email_domains set operation_id=$2,updated_at=now(),version=version+1 where id=$1 and ((desired_state='active' and state in ('registering','dns_pending','testing')) or (desired_state='disconnected' and state in ('disconnecting','action_required')))").bind(id).bind(operation).execute(&mut *tx).await?.rows_affected();
        tx.commit().await?;
        admitted += usize::from(changed == 1);
    }
    Ok(admitted)
}

async fn admit_webshop_domain_reconciliation(store: &Store) -> anyhow::Result<usize> {
    let bucket = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / WEBSHOP_DOMAIN_RECONCILIATION_INTERVAL.as_secs();
    let domains = sqlx::query_as::<_, (Uuid, Uuid, bool)>(
        "select id,workshop_id,
                desired_state='disconnected' and redirect_target is not null
           from control.webshop_domains d
          where ((desired_state='active'
                  and state in ('dns_pending','certificate_pending','testing')
                  and ownership_verified_at is not null)
              or (desired_state='disconnected'
                  and state in ('disconnecting','action_required')))
            and not exists(select 1 from control.operations o
                where o.id=d.operation_id and o.state in ('pending','in_flight','awaiting_reconciliation'))
          order by id limit 500",
    )
    .fetch_all(store.pool())
    .await?;
    let mut admitted = 0;
    for (domain_id, workshop, restore_platform_canonical) in domains {
        let mut tx = store.begin().await?;
        let operation_id = Store::enqueue(
            &mut tx,
            NewOperation {
                kind: OperationKind::WebshopDomainReconcile,
                workshop_id: Some(workshop),
                target_user_id: None,
                desired_epoch: None,
                payload: &json!({
                    "domain_id":domain_id,
                    "reason":"periodic_observation",
                    "restore_platform_canonical":restore_platform_canonical
                }),
                requested_by: None,
                correlation_id: Uuid::new_v4(),
                idempotency_key: &format!("periodic-domain:{domain_id}:{bucket}"),
            },
        )
        .await?;
        let changed = sqlx::query(
            "update control.webshop_domains set operation_id=$2,updated_at=now(),version=version+1
              where id=$1
                and ((desired_state='active'
                      and state in ('dns_pending','certificate_pending','testing')
                      and ownership_verified_at is not null)
                  or (desired_state='disconnected'
                      and state in ('disconnecting','action_required'))) ",
        )
        .bind(domain_id)
        .bind(operation_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        admitted += usize::from(changed == 1);
    }
    Ok(admitted)
}

async fn admit_periodic_tenant_reconciliation(store: &Store) -> anyhow::Result<usize> {
    let domain = std::env::var("CONTROL_TENANT_DOMAIN")
        .map_err(|_| anyhow::anyhow!("CONTROL_TENANT_DOMAIN is required for reconciliation"))?;
    let tenants = sqlx::query_as::<_, (Uuid, Uuid, String, String, String, bool, Value)>(
        "select w.id,d.id,w.slug,d.database_ref,d.public_hostname,
                exists(select 1 from control.workshop_modules m
                       where m.workshop_id=w.id and m.module_key='documents'
                         and m.state='enabled'),
                coalesce((select jsonb_agg(jsonb_build_object(
                    'hostname',h.hostname,'canonical',h.canonical) order by h.hostname)
                    from control.webshop_domains h where h.workshop_id=w.id
                      and h.state in ('testing','active') and h.desired_state='active'),'[]'::jsonb)
           from control.workshops w
           join control.odoo_databases d on d.workshop_id=w.id
          where w.status in ('trial','active','past_due','restricted','suspended')
            and d.kind='primary' and d.deleted_at is null
            and d.public_hostname is not null
            and not exists(
                select 1 from control.release_fleet_runs f
                 where f.state in ('preflighting','preparing','paused','activating')
            )
            and not exists(
                select 1 from control.operations o
                 where o.workshop_id=w.id
                   and o.state in ('pending','in_flight','awaiting_reconciliation')
                   and o.kind in ('tenant.provision','tenant.reconcile',
                                  'tenant.lifecycle','odoo.release.adopt')
            )
          order by w.id",
    )
    .fetch_all(store.pool())
    .await?;
    let bucket = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / TENANT_RECONCILIATION_INTERVAL.as_secs();
    let mut admitted = 0;
    for (
        workshop,
        database_id,
        slug,
        database_ref,
        public_hostname,
        paperless_enabled,
        custom_hostnames,
    ) in tenants
    {
        let payload = json!({
            "database_id":database_id,
            "database_ref":database_ref,
            "public_hostname":public_hostname,
            "paperless_hostname":format!("docs-{slug}.{domain}"),
            "paperless_enabled":paperless_enabled,
            "custom_hostnames":custom_hostnames,
            "reason":"periodic_drift_reconciliation",
        });
        let mut tx = store.begin().await?;
        Store::enqueue(
            &mut tx,
            crate::persistence::NewOperation {
                kind: crate::domain::OperationKind::TenantReconcile,
                workshop_id: Some(workshop),
                target_user_id: None,
                desired_epoch: None,
                payload: &payload,
                requested_by: None,
                correlation_id: Uuid::new_v4(),
                idempotency_key: &format!("periodic-reconcile:{workshop}:{bucket}"),
            },
        )
        .await?;
        tx.commit().await?;
        admitted += 1;
    }
    Ok(admitted)
}

async fn handle(store: &Store, operation: &LeasedOperation) -> Result<(), IntegrationError> {
    tracing::info!(operation=%operation.id,kind=%operation.kind,attempt=operation.attempt,reconciling=operation.reconciling,"handling operation");
    match operation.kind.as_str() {
        "membership.reconcile" => membership(store, operation).await,
        "entitlement.apply" => entitlement(store, operation).await,
        "invoice.capture" => crate::workers::extraction::invoice(store, operation).await,
        "inventory.capture.extract" => {
            crate::workers::extraction::inventory_capture(store, operation).await
        }
        "tenant.provision" => driver(store, operation, "provision").await.map(|_| ()),
        "tenant.reconcile" => driver(store, operation, "reconcile").await.map(|_| ()),
        "tenant.lifecycle" => crate::workers::lifecycle::run(store, operation).await,
        "email.delivery" => crate::workers::email::deliver(store, operation).await,
        "module.enable" => enable_module(store, operation).await,
        "module.restrict" => restrict_module(store, operation).await,
        "webshop-domain.reconcile" => crate::workers::domains::run(store, operation).await,
        "webshop-email-domain.reconcile" => {
            crate::workers::email_domains::run(store, operation).await
        }
        "webshop-onboarding.reconcile" => crate::workers::onboarding::run(store, operation).await,
        "odoo.release.adopt" => crate::workers::release::adopt(store, operation).await,
        "privacy.retention" => crate::workers::privacy::retention(store, operation).await,
        "privacy.data_subject_request" => {
            crate::workers::privacy::data_subject_request(store, operation).await
        }
        _ => Err(IntegrationError::ContractDrift),
    }
}

async fn enable_module(store: &Store, operation: &LeasedOperation) -> Result<(), IntegrationError> {
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
        enable_paperless(store, operation, workshop).await?;
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
    sqlx::query(
        "update control.workshop_modules set state='enabled',enabled_at=now(),version=version+1
         where workshop_id=$1 and module_key=$2 and operation_id=$3",
    )
    .bind(workshop)
    .bind(module_key)
    .bind(operation.id)
    .execute(store.pool())
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
    tracing::info!(operation=%operation_id,reason,"capability restriction admitted");
    Ok(())
}

async fn restrict_module(
    store: &Store,
    operation: &LeasedOperation,
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
        let tenant = sqlx::query_as::<_, (String, String, String)>(
            "select d.database_ref,d.public_hostname,w.slug from control.odoo_databases d
              join control.workshops w on w.id=d.workshop_id
              where d.workshop_id=$1 and d.kind='primary' and d.deleted_at is null
                and d.public_hostname is not null",
        )
        .bind(workshop)
        .fetch_optional(store.pool())
        .await
        .map_err(|_| IntegrationError::Unavailable)?
        .ok_or(IntegrationError::NotFound)?;
        driver_request(store, operation.id, workshop, "restrict", &json!({
            "capability":module_key,"database_ref":tenant.0,"public_hostname":tenant.1,
            "paperless_hostname":format!("docs-{}.{}", tenant.2, configuration("CONTROL_TENANT_DOMAIN")?)
        })).await?
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
    let changed = sqlx::query(
        "update control.workshop_modules set state='restricted',restriction_evidence=$4,
                restricted_at=now(),version=version+1
          where workshop_id=$1 and module_key=$2 and operation_id=$3 and state='restricting'",
    )
    .bind(workshop)
    .bind(module_key)
    .bind(operation.id)
    .bind(evidence)
    .execute(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .rows_affected();
    if changed != 1 {
        return Err(IntegrationError::ContractDrift);
    }
    Ok(())
}

async fn enable_paperless(
    store: &Store,
    operation: &LeasedOperation,
    workshop: Uuid,
) -> Result<(), IntegrationError> {
    let tenant = sqlx::query_as::<_, (Uuid, String, String, String)>(
        "select d.id,w.slug,d.database_ref,d.public_hostname
         from control.workshops w
         join control.odoo_databases d on d.workshop_id=w.id
         where w.id=$1 and w.status<>'deleted' and d.kind='primary'
           and d.deleted_at is null and d.public_hostname is not null",
    )
    .bind(workshop)
    .fetch_optional(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .ok_or(IntegrationError::NotFound)?;
    let paperless_hostname = format!(
        "docs-{}.{}",
        tenant.1,
        configuration("CONTROL_TENANT_DOMAIN")?
    );
    let payload = json!({
        "database_id": tenant.0,
        "database_ref": tenant.2,
        "public_hostname": tenant.3,
        "paperless_hostname": paperless_hostname,
        "paperless_enabled": true,
        "custom_hostnames": routable_custom_hostnames(store, workshop)
            .await.map_err(|_| IntegrationError::Unavailable)?,
    });
    let value = driver_request(store, operation.id, workshop, "reconcile", &payload).await?;
    let paperless = value
        .get("paperless")
        .ok_or(IntegrationError::ContractDrift)?;
    upsert_service(store, workshop, "paperless", paperless, &value).await?;

    let members = sqlx::query_as::<_, (Uuid, i32)>(
        "select user_id,authority_epoch from control.memberships where workshop_id=$1",
    )
    .bind(workshop)
    .fetch_all(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    let mut tx = store
        .begin()
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
                &mut tx,
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
    if let Ok(root) = std::env::var(root_variable) {
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

async fn membership(store: &Store, operation: &LeasedOperation) -> Result<(), IntegrationError> {
    let workshop = operation
        .workshop_id
        .ok_or(IntegrationError::ContractDrift)?;
    let user = operation
        .target_user_id
        .ok_or(IntegrationError::ContractDrift)?;
    let epoch = operation
        .desired_epoch
        .ok_or(IntegrationError::ContractDrift)?;
    let row=sqlx::query_as::<_,(String,Option<String>,String,String,String,i32)>("select u.email,u.display_name,i.subject,m.role,m.status,m.authority_epoch from control.users u join control.external_identities i on i.user_id=u.id join control.memberships m on m.user_id=u.id where u.id=$1 and m.workshop_id=$2")
        .bind(user).bind(workshop).fetch_optional(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?.ok_or(IntegrationError::NotFound)?;
    if row.5 != epoch {
        return Ok(());
    }
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
        store,
        workshop,
        user,
        "rauthy",
        epoch,
        &rauthy_result,
        if active { "ready" } else { "disabled" },
    )
    .await?;
    let odoo_result = async {
        let (url, reference, database_ref) = service(store, workshop, "odoo").await?;
        let client = OdooClient::new(
            &url,
            &secret(&reference)?,
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
        store,
        workshop,
        user,
        "odoo",
        epoch,
        &odoo_result,
        if active { "ready" } else { "disabled" },
    )
    .await?;
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
    .bind(active)
    .fetch_one(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    let paperless_result = if has_paperless_target {
        let result = async {
            let (url, reference, _) = service(store, workshop, "paperless").await?;
            let client = PaperlessClient::new(&url, &secret(&reference)?, Duration::from_secs(20))
                .map_err(|_| IntegrationError::ContractDrift)?;
            let groups = client.ensure_groups(paperless_group_names(&row.3)?).await?;
            client
                .reconcile_user(&row.2, &row.0, active, &groups, row.3 == "owner")
                .await
        }
        .await;
        record_target(
            store,
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
    store: &Store,
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
    sqlx::query("update control.membership_targets set applied_epoch=case when $5 is null then $4 else applied_epoch end,state=$6,safe_error_class=$5,observed_at=now() where workshop_id=$1 and user_id=$2 and target=$3 and desired_epoch=$4")
        .bind(workshop).bind(user).bind(target).bind(epoch).bind(error).bind(state).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
    Ok(())
}

async fn entitlement(store: &Store, operation: &LeasedOperation) -> Result<(), IntegrationError> {
    let workshop = operation
        .workshop_id
        .ok_or(IntegrationError::ContractDrift)?;
    let row=sqlx::query_as::<_,(i64,String,String,Value,Option<time::OffsetDateTime>,String)>("select version,plan,status,limits,expires_at,signature from control.entitlements where workshop_id=$1").bind(workshop).fetch_optional(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?.ok_or(IntegrationError::NotFound)?;
    let (url, reference, database_ref) = service(store, workshop, "odoo").await?;
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
    store: &Store,
    operation: &LeasedOperation,
    action: &str,
) -> Result<Value, IntegrationError> {
    let workshop = operation
        .workshop_id
        .ok_or(IntegrationError::ContractDrift)?;
    let value = driver_request(store, operation.id, workshop, action, &operation.payload).await?;
    for service_name in ["odoo", "paperless"] {
        if let Some(service) = value.get(service_name) {
            upsert_service(store, workshop, service_name, service, &value).await?;
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
        let service_id = sqlx::query_scalar::<_, Uuid>(
            "select id from control.service_instances where workshop_id=$1 and service='odoo'",
        )
        .bind(workshop)
        .fetch_one(store.pool())
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
        let changed = sqlx::query("update control.odoo_databases set service_instance_id=$2,state='ready' where workshop_id=$1 and kind='primary' and database_ref=$3 and public_hostname=$4")
            .bind(workshop).bind(service_id).bind(expected_ref).bind(expected_hostname).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
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
        .fetch_one(store.pool())
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
        sqlx::query("insert into control.tenant_release_adoptions(id,workshop_id,database_id,release_id,registry_version,state,operation_id,target_schema_epoch,started_at,verified_at,activated_at,evidence) select $1,$2,$3,r.id,(r.manifest->>'capability_registry_version')::integer,'active',$4,r.schema_epoch,now(),now(),now(),jsonb_build_object('source','tenant_provisioning','release_id',r.id,'registry_version',(r.manifest->>'capability_registry_version')::integer) from control.application_releases r join control.capability_registry_versions registry on registry.version=(r.manifest->>'capability_registry_version')::integer and registry.active where r.id=$5 and r.status='active' on conflict(workshop_id,database_id,release_id) do nothing")
            .bind(Uuid::new_v4()).bind(workshop).bind(database_id).bind(operation.id).bind(release_id).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
        let adoption_recorded=sqlx::query_scalar::<_,bool>("select exists(select 1 from control.tenant_release_adoptions where workshop_id=$1 and database_id=$2 and release_id=$3 and state='active')")
            .bind(workshop).bind(database_id).bind(release_id).fetch_one(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
        if !adoption_recorded {
            return Err(IntegrationError::ContractDrift);
        }
        sqlx::query("update control.workshops set status='trial',version=version+1 where id=$1 and status='provisioning'").bind(workshop).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
        let owner = sqlx::query_as::<_, (Uuid, i32)>(
            "select user_id,authority_epoch from control.memberships where workshop_id=$1 and role='owner' and status='active'",
        )
        .bind(workshop)
        .fetch_optional(store.pool())
        .await
        .map_err(|_| IntegrationError::Unavailable)?
        .ok_or(IntegrationError::ContractDrift)?;
        let mut tx = store
            .begin()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        seed_membership_targets(&mut tx, workshop, owner.0, owner.1).await?;
        let payload = json!({"active":true});
        let key = format!("provision-owner:{workshop}:{}", owner.1);
        Store::enqueue(
            &mut tx,
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
        tx.commit()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
    }
    Ok(value)
}

async fn driver_request(
    _store: &Store,
    operation_id: Uuid,
    workshop: Uuid,
    action: &str,
    payload: &Value,
) -> Result<Value, IntegrationError> {
    driver_request_with_key(
        operation_id,
        workshop,
        action,
        &operation_id.to_string(),
        payload,
    )
    .await
}

pub(crate) async fn driver_request_with_key(
    _operation_id: Uuid,
    workshop: Uuid,
    action: &str,
    idempotency_key: &str,
    payload: &Value,
) -> Result<Value, IntegrationError> {
    let url = configuration("CONTROL_DEPLOYMENT_DRIVER_URL")?;
    let token = env("CONTROL_DEPLOYMENT_DRIVER_TOKEN")?;
    // First-time Odoo and Paperless initialization can legitimately take several
    // minutes. The operation lease is heartbeated while this request is in flight,
    // and the driver persists idempotent outcomes for ambiguous disconnects.
    let client = http_client(&token, Duration::from_secs(900))?;
    let response = client
        .post(format!(
            "{}/v1/tenants/{workshop}/{action}",
            url.trim_end_matches('/')
        ))
        .header("idempotency-key", idempotency_key)
        .json(payload)
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
        return Err(super_classify(status));
    }
    Ok(value)
}

async fn upsert_service(
    store: &Store,
    workshop: Uuid,
    service_name: &str,
    service: &Value,
    response: &Value,
) -> Result<(), IntegrationError> {
    let base = service
        .get("base_url")
        .and_then(Value::as_str)
        .ok_or(IntegrationError::ContractDrift)?;
    let secret_ref = service
        .get("secret_ref")
        .and_then(Value::as_str)
        .ok_or(IntegrationError::ContractDrift)?;
    sqlx::query("insert into control.service_instances(id,workshop_id,service,base_url,secret_ref,release_id,health,applied_epoch) values($1,$2,$3,$4,$5,$6,'ready',1) on conflict(workshop_id,service) do update set base_url=excluded.base_url,secret_ref=excluded.secret_ref,release_id=excluded.release_id,health='ready',last_observed_at=now()")
        .bind(Uuid::new_v4()).bind(workshop).bind(service_name).bind(base).bind(secret_ref).bind(response.get("release_id").and_then(Value::as_str)).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
    Ok(())
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

fn http_client(token: &str, timeout: Duration) -> Result<reqwest::Client, IntegrationError> {
    let mut value = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| IntegrationError::ContractDrift)?;
    value.set_sensitive(true);
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::AUTHORIZATION, value);
    reqwest::Client::builder()
        .default_headers(headers)
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| IntegrationError::ContractDrift)
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
    use super::*;

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
            .bind(format!("_makersbrain-challenge.{}.example.test", domain.simple()))
            .bind(format!("makersbrain-verification={}", &domain.simple().to_string()[..32]))
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
